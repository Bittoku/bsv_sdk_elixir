defmodule BSV.Wallet.ProtoWallet do
  @moduledoc """
  A foundational wallet capable of cryptographic operations (key derivation,
  encrypt/decrypt, sign/verify, HMAC) but not transaction management or
  blockchain interaction.

  Implements the `BSV.Wallet` behaviour for crypto-only operations.
  """

  alias BSV.{PrivateKey, SymmetricKey, Crypto}
  alias BSV.Wallet.KeyDeriver
  alias BSV.Wallet.Types.{Counterparty, EncryptionArgs}

  @enforce_keys [:key_deriver]
  defstruct [:key_deriver]

  @type t :: %__MODULE__{key_deriver: KeyDeriver.t()}

  @behaviour BSV.Wallet

  @doc "Create a ProtoWallet from a private key."
  @spec from_private_key(PrivateKey.t()) :: t()
  def from_private_key(%PrivateKey{} = pk) do
    %__MODULE__{key_deriver: KeyDeriver.new(pk)}
  end

  @doc "Create a ProtoWallet from a KeyDeriver."
  @spec from_key_deriver(KeyDeriver.t()) :: t()
  def from_key_deriver(%KeyDeriver{} = kd) do
    %__MODULE__{key_deriver: kd}
  end

  @doc "Create an 'anyone' ProtoWallet (scalar=1)."
  @spec anyone() :: t()
  def anyone, do: %__MODULE__{key_deriver: KeyDeriver.new(nil)}

  @doc "The identity public key."
  @spec identity_key(t()) :: BSV.PublicKey.t()
  def identity_key(%__MODULE__{key_deriver: kd}), do: KeyDeriver.identity_key(kd)

  # --- BSV.Wallet behaviour ---

  @doc "Derive a public key based on encryption args, or return the identity key."
  @impl BSV.Wallet
  def get_public_key(%__MODULE__{key_deriver: kd}, opts) do
    if Keyword.get(opts, :identity_key, false) do
      {:ok, KeyDeriver.identity_key(kd)}
    else
      enc = Keyword.fetch!(opts, :encryption_args)
      for_self = Keyword.get(opts, :for_self, false)
      counterparty = default_counterparty_self(enc.counterparty)

      KeyDeriver.derive_public_key(kd, enc.protocol_id, enc.key_id, counterparty, for_self)
    end
  end

  @doc "Encrypt plaintext using a derived symmetric key."
  @impl BSV.Wallet
  def encrypt(%__MODULE__{key_deriver: kd}, %EncryptionArgs{} = enc, plaintext) do
    counterparty = default_counterparty_self(enc.counterparty)

    with {:ok, key} <- KeyDeriver.derive_symmetric_key(kd, enc.protocol_id, enc.key_id, counterparty) do
      SymmetricKey.encrypt(key, plaintext)
    end
  end

  @doc """
  Decrypt ciphertext using a derived symmetric key.

  Automatically falls back to legacy key derivation (raw ECDH x-coordinate)
  if decryption with the current KDF (SHA-256) fails, for backward compatibility.
  """
  @impl BSV.Wallet
  def decrypt(%__MODULE__{key_deriver: kd}, %EncryptionArgs{} = enc, ciphertext) do
    counterparty = default_counterparty_self(enc.counterparty)

    with {:ok, key} <- KeyDeriver.derive_symmetric_key(kd, enc.protocol_id, enc.key_id, counterparty) do
      case SymmetricKey.decrypt(key, ciphertext) do
        {:ok, _} = result ->
          result

        {:error, :decrypt_failed} ->
          # Legacy fallback: try raw x-coordinate key derivation
          with {:ok, legacy_key} <- KeyDeriver.derive_symmetric_key(kd, enc.protocol_id, enc.key_id, counterparty, legacy: true) do
            SymmetricKey.decrypt(legacy_key, ciphertext)
          end
      end
    end
  end

  @doc "Create a DER-encoded signature using a derived private key."
  @impl BSV.Wallet
  def create_signature(%__MODULE__{key_deriver: kd}, %EncryptionArgs{} = enc, data, hash_to_sign) do
    data_hash = if hash_to_sign != nil and byte_size(hash_to_sign) > 0 do
      hash_to_sign
    else
      Crypto.sha256(data)
    end

    counterparty = default_counterparty_anyone(enc.counterparty)

    with {:ok, priv_key} <- KeyDeriver.derive_private_key(kd, enc.protocol_id, enc.key_id, counterparty) do
      PrivateKey.sign(priv_key, data_hash)
    end
  end

  @doc "Verify a DER-encoded signature using a derived public key."
  @impl BSV.Wallet
  def verify_signature(%__MODULE__{key_deriver: kd}, %EncryptionArgs{} = enc, data, hash_to_verify, signature, opts) do
    if (data == nil or data == <<>>) and (hash_to_verify == nil or hash_to_verify == <<>>) do
      {:error, "data or hash_to_verify must be provided"}
    else
      data_hash = if hash_to_verify != nil and byte_size(hash_to_verify) > 0 do
        hash_to_verify
      else
        Crypto.sha256(data)
      end

      counterparty = default_counterparty_self(enc.counterparty)
      for_self = Keyword.get(opts, :for_self, false)

      with {:ok, pub_key} <- KeyDeriver.derive_public_key(kd, enc.protocol_id, enc.key_id, counterparty, for_self) do
        {:ok, BSV.PublicKey.verify(pub_key, data_hash, signature)}
      end
    end
  end

  @doc "Create an HMAC-SHA256 using a derived symmetric key."
  @impl BSV.Wallet
  def create_hmac(%__MODULE__{key_deriver: kd}, %EncryptionArgs{} = enc, data) do
    counterparty = default_counterparty_self(enc.counterparty)

    with {:ok, key} <- KeyDeriver.derive_symmetric_key(kd, enc.protocol_id, enc.key_id, counterparty) do
      hmac = Crypto.sha256_hmac(data, SymmetricKey.to_bytes(key))
      {:ok, hmac}
    end
  end

  @doc """
  Verify an HMAC-SHA256 using a derived symmetric key.

  Falls back to legacy key derivation if the current key doesn't match,
  for backward compatibility with HMACs created by v0.1.
  """
  @impl BSV.Wallet
  def verify_hmac(%__MODULE__{key_deriver: kd}, %EncryptionArgs{} = enc, data, hmac) do
    counterparty = default_counterparty_self(enc.counterparty)

    with {:ok, key} <- KeyDeriver.derive_symmetric_key(kd, enc.protocol_id, enc.key_id, counterparty) do
      computed = Crypto.sha256_hmac(data, SymmetricKey.to_bytes(key))

      if Crypto.secure_compare(computed, hmac) do
        {:ok, true}
      else
        # Legacy fallback
        with {:ok, legacy_key} <- KeyDeriver.derive_symmetric_key(kd, enc.protocol_id, enc.key_id, counterparty, legacy: true) do
          legacy_computed = Crypto.sha256_hmac(data, SymmetricKey.to_bytes(legacy_key))
          {:ok, Crypto.secure_compare(legacy_computed, hmac)}
        end
      end
    end
  end

  # --- Private helpers ---

  defp default_counterparty_self(%Counterparty{type: :uninitialized}),
    do: %Counterparty{type: :self}

  defp default_counterparty_self(cp), do: cp

  defp default_counterparty_anyone(%Counterparty{type: :uninitialized}),
    do: %Counterparty{type: :anyone}

  defp default_counterparty_anyone(cp), do: cp
end
