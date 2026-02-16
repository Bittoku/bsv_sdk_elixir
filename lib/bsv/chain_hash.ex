defmodule BSV.ChainHash do
  @moduledoc """
  A 32-byte hash used for block and transaction identifiers in Bitcoin.
  Hex display follows Bitcoin convention (byte-reversed).
  """

  @enforce_keys [:bytes]
  defstruct [:bytes]

  @type t :: %__MODULE__{bytes: <<_::256>>}

  @doc "Create a ChainHash from 32 raw bytes."
  @spec from_bytes(<<_::256>>) :: t()
  def from_bytes(<<bytes::binary-size(32)>>), do: %__MODULE__{bytes: bytes}

  @doc "Create a ChainHash from a hex string (byte-reversed, Bitcoin convention)."
  @spec from_hex(String.t()) :: {:ok, t()} | {:error, String.t()}
  def from_hex(hex) when byte_size(hex) == 64 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} -> {:ok, %__MODULE__{bytes: reverse(bytes)}}
      :error -> {:error, "invalid hex"}
    end
  end

  def from_hex(_), do: {:error, "hex must be 64 characters"}

  @doc "Create a ChainHash from hex, raising on error."
  @spec from_hex!(String.t()) :: t()
  def from_hex!(hex) do
    case from_hex(hex) do
      {:ok, hash} -> hash
      {:error, reason} -> raise ArgumentError, reason
    end
  end

  @doc "Convert to hex string (byte-reversed)."
  @spec to_hex(t()) :: String.t()
  def to_hex(%__MODULE__{bytes: bytes}), do: bytes |> reverse() |> Base.encode16(case: :lower)

  @doc "Get raw 32 bytes."
  @spec to_bytes(t()) :: <<_::256>>
  def to_bytes(%__MODULE__{bytes: bytes}), do: bytes

  defp reverse(bin), do: bin |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

  defimpl String.Chars do
    def to_string(hash), do: BSV.ChainHash.to_hex(hash)
  end
end
