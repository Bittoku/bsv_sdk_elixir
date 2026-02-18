defmodule BSV.VarInt do
  @moduledoc """
  Bitcoin variable-length integer encoding/decoding.
  """

  @doc "Encode an integer as a Bitcoin VarInt."
  @spec encode(non_neg_integer()) :: binary()
  def encode(n) when n < 0xFD, do: <<n::8>>
  def encode(n) when n <= 0xFFFF, do: <<0xFD, n::little-16>>
  def encode(n) when n <= 0xFFFFFFFF, do: <<0xFE, n::little-32>>
  def encode(n), do: <<0xFF, n::little-64>>

  @doc """
  Decode a Bitcoin VarInt from binary, returning value and remaining bytes.

  Optionally pass `max` to reject values above a threshold (prevents
  resource exhaustion when VarInt controls allocation sizes).
  """
  @spec decode(binary(), non_neg_integer() | nil) :: {:ok, {non_neg_integer(), binary()}} | {:error, String.t()}
  def decode(data, max \\ nil)

  def decode(<<0xFF, n::little-64, rest::binary>>, max), do: check_max(n, rest, max)
  def decode(<<0xFE, n::little-32, rest::binary>>, max), do: check_max(n, rest, max)
  def decode(<<0xFD, n::little-16, rest::binary>>, max), do: check_max(n, rest, max)
  def decode(<<n::8, rest::binary>>, max), do: check_max(n, rest, max)
  def decode(<<>>, _max), do: {:error, "empty input"}
  def decode(_, _max), do: {:error, "insufficient data"}

  defp check_max(n, rest, nil), do: {:ok, {n, rest}}
  defp check_max(n, rest, max) when n <= max, do: {:ok, {n, rest}}
  defp check_max(n, _rest, max), do: {:error, "VarInt value #{n} exceeds maximum #{max}"}
end
