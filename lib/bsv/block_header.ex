defmodule BSV.BlockHeader do
  @moduledoc """
  An 80-byte block header providing a summary of a Bitcoin block.

  Contains the version, previous block hash, merkle root, timestamp,
  difficulty target (bits), and nonce. The block hash is the double-SHA256
  of the serialized 80-byte header.
  """

  alias BSV.Crypto

  defstruct [:version, :prev_hash, :merkle_root, :time, :bits, :nonce]

  @typedoc "Block header"
  @type t :: %__MODULE__{
          version: non_neg_integer(),
          prev_hash: <<_::256>>,
          merkle_root: <<_::256>>,
          time: non_neg_integer(),
          bits: non_neg_integer(),
          nonce: non_neg_integer()
        }

  @header_size 80

  @doc """
  Parse a block header from a binary.

  Returns `{:ok, header, rest}` or `{:error, reason}`.
  """
  @spec from_binary(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def from_binary(<<
        version::little-32,
        prev_hash::binary-32,
        merkle_root::binary-32,
        time::little-32,
        bits::little-32,
        nonce::little-32,
        rest::binary
      >>) do
    {:ok,
     %__MODULE__{
       version: version,
       prev_hash: prev_hash,
       merkle_root: merkle_root,
       time: time,
       bits: bits,
       nonce: nonce
     }, rest}
  end

  def from_binary(_), do: {:error, :insufficient_header_data}

  @doc """
  Parse a block header from a hex-encoded string.
  """
  @spec from_hex(String.t()) :: {:ok, t()} | {:error, term()}
  def from_hex(hex) when is_binary(hex) do
    with {:ok, bin} <- safe_decode16(hex),
         {:ok, header, _rest} <- from_binary(bin) do
      {:ok, header}
    end
  end

  @doc """
  Serialize a block header to its 80-byte binary representation.
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = h) do
    <<
      h.version::little-32,
      h.prev_hash::binary,
      h.merkle_root::binary,
      h.time::little-32,
      h.bits::little-32,
      h.nonce::little-32
    >>
  end

  @doc """
  Serialize a block header to a hex-encoded string.
  """
  @spec to_hex(t()) :: String.t()
  def to_hex(%__MODULE__{} = h), do: h |> to_binary() |> Base.encode16(case: :lower)

  @doc """
  Compute the block hash (double SHA-256 of the 80-byte header), returned
  as a 32-byte binary in internal byte order (little-endian, as used in
  Bitcoin's wire protocol).
  """
  @spec hash(t()) :: <<_::256>>
  def hash(%__MODULE__{} = h), do: Crypto.sha256d(to_binary(h))

  @doc """
  Compute the block hash as a hex string in display byte order (reversed,
  as shown in block explorers).
  """
  @spec hash_hex(t()) :: String.t()
  def hash_hex(%__MODULE__{} = h) do
    h |> hash() |> reverse() |> Base.encode16(case: :lower)
  end

  @doc """
  Return the size in bytes of a serialized block header (always 80).
  """
  @spec size() :: 80
  def size, do: @header_size

  defp reverse(<<>>), do: <<>>
  defp reverse(bin), do: bin |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

  defp safe_decode16(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :invalid_hex}
    end
  end
end
