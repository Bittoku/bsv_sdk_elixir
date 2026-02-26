defmodule BSV.ExtKey do
  @moduledoc """
  BIP-32 hierarchical deterministic (HD) extended keys.

  Supports creating master keys from a seed (or mnemonic), deriving child keys
  via derivation paths (e.g. `"m/44'/0'/0'/0/0"`), and serializing to/from
  xprv/xpub format.

  ## Examples

      iex> {:ok, master} = BSV.ExtKey.from_seed(<<0::512>>)
      iex> master.depth
      0

      iex> child = BSV.ExtKey.derive(master, "m/44'/0'/0'")
      iex> child.depth
      3
  """

  alias BSV.{Crypto, PrivateKey, PublicKey, Base58}

  defstruct version: nil,
            depth: 0,
            fingerprint: <<0::32>>,
            child_index: 0,
            chain_code: <<0::256>>,
            privkey: nil,
            pubkey: nil

  @typedoc "Extended key"
  @type t :: %__MODULE__{
          version: binary(),
          depth: non_neg_integer(),
          fingerprint: <<_::32>>,
          child_index: non_neg_integer(),
          chain_code: <<_::256>>,
          privkey: PrivateKey.t() | nil,
          pubkey: PublicKey.t()
        }

  @typedoc "Serialized xprv string"
  @type xprv :: String.t()

  @typedoc "Serialized xpub string"
  @type xpub :: String.t()

  @typedoc "BIP-32 derivation path"
  @type derivation_path :: String.t()

  # Version bytes (mainnet)
  @xprv_version <<0x04, 0x88, 0xAD, 0xE4>>
  @xpub_version <<0x04, 0x88, 0xB2, 0x1E>>

  # Testnet versions
  @tprv_version <<0x04, 0x35, 0x83, 0x94>>
  @tpub_version <<0x04, 0x35, 0x87, 0xCF>>

  @mersenne_prime 2_147_483_647
  @hardened_offset @mersenne_prime + 1

  # secp256k1 curve order
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  defguardp normal?(index) when index >= 0 and index <= @mersenne_prime
  defguardp hardened?(index) when index > @mersenne_prime

  @doc """
  Generate a new random master extended key.
  """
  @spec new() :: t()
  def new, do: from_seed!(:crypto.strong_rand_bytes(64))

  @doc """
  Create a master extended key from a binary seed (16–64 bytes).

  Typically the seed comes from `BSV.Mnemonic.to_seed/2`.
  """
  @spec from_seed(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def from_seed(seed, opts \\ []) when is_binary(seed) do
    seed = maybe_decode(seed, Keyword.get(opts, :encoding))
    version = priv_version(Keyword.get(opts, :network, :main))

    if bit_size(seed) >= 128 and bit_size(seed) <= 512 do
      <<d::binary-32, chain_code::binary-32>> =
        :crypto.mac(:hmac, :sha512, "Bitcoin seed", seed)

      privkey = %PrivateKey{raw: d}
      pubkey = PublicKey.from_private_key(privkey)

      {:ok,
       %__MODULE__{
         version: version,
         chain_code: chain_code,
         privkey: privkey,
         pubkey: pubkey
       }}
    else
      {:error, {:invalid_seed_length, byte_size(seed)}}
    end
  end

  @doc """
  As `from_seed/2` but raises on error.
  """
  @spec from_seed!(binary(), keyword()) :: t()
  def from_seed!(seed, opts \\ []) do
    case from_seed(seed, opts) do
      {:ok, key} -> key
      {:error, reason} -> raise ArgumentError, "invalid seed: #{inspect(reason)}"
    end
  end

  @doc """
  Decode an xprv or xpub string into an extended key.
  """
  @spec from_string(xprv() | xpub()) :: {:ok, t()} | {:error, term()}
  def from_string(<<"xprv", _::binary>> = str), do: decode_xprv(str, @xprv_version)
  def from_string(<<"tprv", _::binary>> = str), do: decode_xprv(str, @tprv_version)
  def from_string(<<"xpub", _::binary>> = str), do: decode_xpub(str, @xpub_version)
  def from_string(<<"tpub", _::binary>> = str), do: decode_xpub(str, @tpub_version)
  def from_string(_), do: {:error, :unrecognized_prefix}

  @doc """
  As `from_string/1` but raises on error.
  """
  @spec from_string!(xprv() | xpub()) :: t()
  def from_string!(str) do
    case from_string(str) do
      {:ok, key} -> key
      {:error, reason} -> raise ArgumentError, "invalid extended key: #{inspect(reason)}"
    end
  end

  @doc """
  Convert an extended private key to its public counterpart (drops the private key).
  """
  @spec to_public(t()) :: t()
  def to_public(%__MODULE__{version: @xprv_version} = k),
    do: %{k | version: @xpub_version, privkey: nil}

  def to_public(%__MODULE__{version: @tprv_version} = k),
    do: %{k | version: @tpub_version, privkey: nil}

  def to_public(%__MODULE__{privkey: nil} = k), do: k

  @doc """
  Serialize an extended key to xprv/xpub string.
  """
  @spec to_string(t()) :: xprv() | xpub()
  def to_string(%__MODULE__{privkey: %PrivateKey{raw: raw}} = k) do
    data =
      <<k.version::binary-4, k.depth::8, k.fingerprint::binary, k.child_index::32,
        k.chain_code::binary, 0::8, raw::binary>>

    Base58.check_encode_raw(data)
  end

  def to_string(%__MODULE__{privkey: nil, pubkey: %PublicKey{point: point}} = k) do
    data =
      <<k.version::binary-4, k.depth::8, k.fingerprint::binary, k.child_index::32,
        k.chain_code::binary, point::binary>>

    Base58.check_encode_raw(data)
  end

  @doc """
  Derive a child key from a derivation path.

  Paths follow BIP-32 format: `"m/44'/0'/0'/0/0"` for private derivation,
  `"M/44'/0'/0'/0/0"` for public derivation.

  Hardened indices use `'` suffix. Hardened public derivation is not possible.
  """
  @spec derive(t(), derivation_path()) :: t()
  def derive(%__MODULE__{} = key, path) when is_binary(path) do
    unless String.match?(path, ~r/^[mM](\/\d+'?)+/) do
      raise ArgumentError, "invalid derivation path: #{path}"
    end

    {kind, indices} = parse_path(path)
    derive_list(key, kind, indices)
  end

  # -- Path parsing --

  defp parse_path(<<"m/", rest::binary>>), do: {:private, parse_indices(rest)}
  defp parse_path(<<"M/", rest::binary>>), do: {:public, parse_indices(rest)}

  defp parse_indices(path) do
    path
    |> String.split("/")
    |> Enum.map(fn chunk ->
      case Regex.run(~r/^(\d+)(')?$/, chunk) do
        [_, num, "'"] -> String.to_integer(num) + @hardened_offset
        [_, num] -> String.to_integer(num)
        _ -> raise ArgumentError, "invalid path segment: #{chunk}"
      end
    end)
  end

  # -- Derivation --

  defp derive_list(key, _kind, []), do: key

  defp derive_list(%{privkey: %PrivateKey{}} = key, :public, indices),
    do: derive_list(to_public(key), :public, indices)

  defp derive_list(%{privkey: nil}, :private, _),
    do: raise(ArgumentError, "cannot derive private child from public parent")

  defp derive_list(key, kind, [index | rest]) do
    {privkey, pubkey, child_chain} = derive_child(key, index)

    child = %__MODULE__{
      version: key.version,
      depth: key.depth + 1,
      fingerprint: fingerprint(key),
      child_index: index,
      chain_code: child_chain,
      privkey: privkey,
      pubkey: pubkey
    }

    derive_list(child, kind, rest)
  end

  # Normal child from private or public parent
  defp derive_child(%{pubkey: %PublicKey{point: point}} = key, index) when normal?(index) do
    <<point::binary, index::32>>
    |> hmac512(key.chain_code)
    |> derive_keypair(key)
  end

  # Hardened child from private parent only
  defp derive_child(%{privkey: %PrivateKey{raw: raw}} = key, index) when hardened?(index) do
    <<0::8, raw::binary, index::32>>
    |> hmac512(key.chain_code)
    |> derive_keypair(key)
  end

  defp derive_child(%{privkey: nil}, index) when hardened?(index),
    do: raise(ArgumentError, "cannot derive hardened child from public parent")

  # Private parent → private child
  defp derive_keypair(
         <<derived::unsigned-256, child_chain::binary-32>>,
         %{privkey: %PrivateKey{raw: raw}}
       ) do
    d = :binary.decode_unsigned(raw, :big)
    child_d = rem(derived + d, @n)

    if child_d == 0 or derived >= @n do
      raise ArgumentError, "invalid child key per BIP-32 (zero or >= curve order)"
    end

    child_raw = child_d |> :binary.encode_unsigned(:big) |> pad32()
    privkey = %PrivateKey{raw: child_raw}
    {privkey, PublicKey.from_private_key(privkey), child_chain}
  end

  # Public parent → public child
  defp derive_keypair(
         <<derived::unsigned-256, child_chain::binary-32>>,
         %{privkey: nil, pubkey: parent_pub}
       ) do
    if derived >= @n do
      raise ArgumentError, "invalid child key per BIP-32 (derived >= curve order)"
    end

    # G * derived_scalar
    offset_raw = derived |> :binary.encode_unsigned(:big) |> pad32()

    case PrivateKey.from_bytes(offset_raw) do
      {:ok, offset_priv} ->
        offset_pub = PublicKey.from_private_key(offset_priv)

        case PublicKey.point_add(parent_pub, offset_pub) do
          {:ok, child_pub} -> {nil, child_pub, child_chain}
          {:error, reason} -> raise ArgumentError, "point addition failed: #{reason}"
        end

      {:error, _} ->
        raise ArgumentError, "invalid child key per BIP-32"
    end
  end

  # -- Helpers --

  defp fingerprint(%{pubkey: %PublicKey{point: point}}) do
    <<fp::binary-4, _::binary>> = Crypto.hash160(point)
    fp
  end

  defp hmac512(data, key), do: :crypto.mac(:hmac, :sha512, key, data)

  defp pad32(bin) when byte_size(bin) >= 32, do: bin
  defp pad32(bin), do: :binary.copy(<<0>>, 32 - byte_size(bin)) <> bin

  defp maybe_decode(data, :hex), do: Base.decode16!(data, case: :mixed)
  defp maybe_decode(data, :base64), do: Base.decode64!(data)
  defp maybe_decode(data, _), do: data

  defp priv_version(:main), do: @xprv_version
  defp priv_version(:test), do: @tprv_version
  defp priv_version(_), do: @xprv_version

  defp decode_xprv(str, version) do
    with {:ok, data} when byte_size(data) == 78 <- Base58.check_decode_raw(str),
         <<^version::binary-4, depth::8, fp::binary-4, child_index::32, chain::binary-32, 0::8,
           d::binary-32>> <- data do
      privkey = %PrivateKey{raw: d}
      pubkey = PublicKey.from_private_key(privkey)

      {:ok,
       %__MODULE__{
         version: version,
         depth: depth,
         fingerprint: fp,
         child_index: child_index,
         chain_code: chain,
         privkey: privkey,
         pubkey: pubkey
       }}
    else
      _ -> {:error, :invalid_xprv}
    end
  end

  defp decode_xpub(str, version) do
    with {:ok, data} when byte_size(data) == 78 <- Base58.check_decode_raw(str),
         <<^version::binary-4, depth::8, fp::binary-4, child_index::32, chain::binary-32,
           pubkey_bytes::binary-33>> <- data,
         {:ok, pubkey} <- PublicKey.from_bytes(pubkey_bytes) do
      {:ok,
       %__MODULE__{
         version: version,
         depth: depth,
         fingerprint: fp,
         child_index: child_index,
         chain_code: chain,
         pubkey: pubkey
       }}
    else
      _ -> {:error, :invalid_xpub}
    end
  end
end
