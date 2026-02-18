defmodule BSV.Wallet.KeyDeriver do
  @moduledoc """
  BRC-42/43 key derivation.

  Derives private, public, and symmetric keys from a root private key using
  the BRC-42 invoice number scheme.
  """

  alias BSV.PrivateKey
  alias BSV.PublicKey
  alias BSV.SymmetricKey
  alias BSV.Wallet.Types.{Protocol, Counterparty}

  @enforce_keys [:root_key]
  defstruct [:root_key]

  @type t :: %__MODULE__{root_key: PrivateKey.t()}

  @anyone_key_bytes <<0::248, 1::8>>

  @doc """
  Create a new KeyDeriver. If no private key is given, uses the "anyone" key (scalar=1).
  """
  @spec new(PrivateKey.t() | nil) :: t()
  def new(nil), do: %__MODULE__{root_key: anyone_private_key()}
  def new(%PrivateKey{} = pk), do: %__MODULE__{root_key: pk}

  @doc "The identity public key (root key's public key)."
  @spec identity_key(t()) :: PublicKey.t()
  def identity_key(%__MODULE__{root_key: pk}), do: PrivateKey.to_public_key(pk)

  @doc "Hex-encoded compressed identity public key."
  @spec identity_key_hex(t()) :: String.t()
  def identity_key_hex(%__MODULE__{} = kd), do: Base.encode16(identity_key(kd).point, case: :lower)

  @doc """
  Derive a symmetric key for the given protocol, key ID, and counterparty.

  Derives both a public and private key, then computes their ECDH shared secret.
  The x-coordinate is passed through SHA-256 before use as the symmetric key.

  ## Migration

  Pass `legacy: true` to derive using the legacy method (raw x-coordinate).
  This is used internally for backward-compatible decryption fallback.
  """
  @spec derive_symmetric_key(t(), Protocol.t(), String.t(), Counterparty.t(), keyword()) ::
          {:ok, SymmetricKey.t()} | {:error, String.t()}
  def derive_symmetric_key(kd, protocol, key_id, counterparty, opts \\ [])

  def derive_symmetric_key(%__MODULE__{} = kd, %Protocol{} = protocol, key_id, %Counterparty{} = counterparty, opts) do
    legacy = Keyword.get(opts, :legacy, false)

    effective = if counterparty.type == :anyone do
      %Counterparty{type: :other, public_key: anyone_public_key()}
    else
      counterparty
    end

    with {:ok, derived_pub} <- derive_public_key(kd, protocol, key_id, effective, false),
         {:ok, derived_priv} <- derive_private_key(kd, protocol, key_id, effective) do
      {:ok, shared} = PrivateKey.derive_shared_secret(derived_priv, derived_pub)
      <<_prefix::8, x_coord::binary-size(32)>> = shared.point

      key_bytes = if legacy, do: x_coord, else: BSV.Crypto.sha256(x_coord)
      {:ok, SymmetricKey.new(key_bytes)}
    end
  end

  @doc """
  Derive a public key for the given protocol, key ID, counterparty, and direction.

  If `for_self` is true, derives the key corresponding to our own private key
  (what the counterparty would compute for us). Otherwise derives the counterparty's key.
  """
  @spec derive_public_key(t(), Protocol.t(), String.t(), Counterparty.t(), boolean()) ::
          {:ok, PublicKey.t()} | {:error, String.t()}
  def derive_public_key(%__MODULE__{root_key: root} = kd, %Protocol{} = protocol, key_id, %Counterparty{} = counterparty, for_self) do
    with {:ok, counterparty_key} <- normalize_counterparty(kd, counterparty),
         {:ok, invoice_number} <- compute_invoice_number(protocol, key_id) do
      if for_self do
        with {:ok, child_priv} <- PrivateKey.derive_child(root, counterparty_key, invoice_number) do
          {:ok, PrivateKey.to_public_key(child_priv)}
        end
      else
        PublicKey.derive_child(counterparty_key, root, invoice_number)
      end
    end
  end

  @doc "Derive a private key for the given protocol, key ID, and counterparty."
  @spec derive_private_key(t(), Protocol.t(), String.t(), Counterparty.t()) ::
          {:ok, PrivateKey.t()} | {:error, String.t()}
  def derive_private_key(%__MODULE__{root_key: root} = kd, %Protocol{} = protocol, key_id, %Counterparty{} = counterparty) do
    with {:ok, counterparty_key} <- normalize_counterparty(kd, counterparty),
         {:ok, invoice_number} <- compute_invoice_number(protocol, key_id) do
      PrivateKey.derive_child(root, counterparty_key, invoice_number)
    end
  end

  @doc """
  Reveal the specific key association (HMAC of shared secret + invoice number).
  """
  @spec reveal_specific_secret(t(), Counterparty.t(), Protocol.t(), String.t()) ::
          {:ok, binary()} | {:error, String.t()}
  def reveal_specific_secret(%__MODULE__{root_key: root} = kd, %Counterparty{} = counterparty, %Protocol{} = protocol, key_id) do
    with {:ok, counterparty_key} <- normalize_counterparty(kd, counterparty),
         {:ok, shared} <- PrivateKey.derive_shared_secret(root, counterparty_key),
         {:ok, invoice_number} <- compute_invoice_number(protocol, key_id) do
      hmac = BSV.Crypto.sha256_hmac(invoice_number, shared.point)
      {:ok, hmac}
    end
  end

  @doc """
  Reveal the counterparty shared secret. Cannot be used for 'self'.
  """
  @spec reveal_counterparty_secret(t(), Counterparty.t()) ::
          {:ok, PublicKey.t()} | {:error, String.t()}
  def reveal_counterparty_secret(%__MODULE__{}, %Counterparty{type: :self}) do
    {:error, "counterparty secrets cannot be revealed for counterparty=self"}
  end

  def reveal_counterparty_secret(%__MODULE__{root_key: root} = kd, %Counterparty{} = counterparty) do
    with {:ok, counterparty_key} <- normalize_counterparty(kd, counterparty) do
      # Verify counterparty is not actually self
      self_pub = PrivateKey.to_public_key(root)
      {:ok, key_by_self} = PrivateKey.derive_child(root, self_pub, "test")
      {:ok, key_by_cp} = PrivateKey.derive_child(root, counterparty_key, "test")

      if key_by_self.raw == key_by_cp.raw do
        {:error, "counterparty secrets cannot be revealed if counterparty key is self"}
      else
        PrivateKey.derive_shared_secret(root, counterparty_key)
      end
    end
  end

  # --- Private ---

  @doc false
  @spec normalize_counterparty(t(), Counterparty.t()) :: {:ok, PublicKey.t()} | {:error, String.t()}
  def normalize_counterparty(%__MODULE__{root_key: root}, %Counterparty{type: :self}),
    do: {:ok, PrivateKey.to_public_key(root)}

  def normalize_counterparty(%__MODULE__{}, %Counterparty{type: :anyone}),
    do: {:ok, anyone_public_key()}

  def normalize_counterparty(%__MODULE__{}, %Counterparty{type: :other, public_key: nil}),
    do: {:error, "counterparty public key required for other"}

  def normalize_counterparty(%__MODULE__{}, %Counterparty{type: :other, public_key: pk}),
    do: {:ok, pk}

  def normalize_counterparty(%__MODULE__{}, %Counterparty{type: :uninitialized}),
    do: {:error, "invalid counterparty, must be self, other, or anyone"}

  @doc false
  @spec compute_invoice_number(Protocol.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def compute_invoice_number(%Protocol{security_level: sl}, _key_id) when sl < 0 or sl > 2 do
    {:error, "protocol security level must be 0, 1, or 2"}
  end

  def compute_invoice_number(%Protocol{}, "") do
    {:error, "key IDs must be 1 character or more"}
  end

  def compute_invoice_number(%Protocol{}, key_id) when byte_size(key_id) > 800 do
    {:error, "key IDs must be 800 characters or less"}
  end

  def compute_invoice_number(%Protocol{security_level: sl, protocol: protocol}, key_id) do
    name = protocol |> String.trim() |> String.downcase()

    cond do
      String.length(name) < 5 ->
        {:error, "protocol names must be 5 characters or more"}

      String.length(name) > 400 and String.starts_with?(name, "specific linkage revelation ") and String.length(name) > 430 ->
        {:error, "specific linkage revelation protocol names must be 430 characters or less"}

      String.length(name) > 400 and not String.starts_with?(name, "specific linkage revelation ") ->
        {:error, "protocol names must be 400 characters or less"}

      String.contains?(name, "  ") ->
        {:error, "protocol names cannot contain multiple consecutive spaces (\"  \")"}

      not Regex.match?(~r/^[a-z0-9 ]+$/, name) ->
        {:error, "protocol names can only contain letters, numbers and spaces"}

      String.ends_with?(name, " protocol") ->
        {:error, "no need to end your protocol name with \" protocol\""}

      true ->
        {:ok, "#{sl}-#{name}-#{key_id}"}
    end
  end

  @doc false
  def anyone_private_key do
    {:ok, key} = PrivateKey.from_bytes(@anyone_key_bytes)
    key
  end

  @doc false
  def anyone_public_key do
    PrivateKey.to_public_key(anyone_private_key())
  end
end
