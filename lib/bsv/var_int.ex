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

  @doc "Decode a Bitcoin VarInt from binary, returning value and remaining bytes."
  @spec decode(binary()) :: {:ok, {non_neg_integer(), binary()}} | {:error, String.t()}
  def decode(<<0xFF, n::little-64, rest::binary>>), do: {:ok, {n, rest}}
  def decode(<<0xFE, n::little-32, rest::binary>>), do: {:ok, {n, rest}}
  def decode(<<0xFD, n::little-16, rest::binary>>), do: {:ok, {n, rest}}
  def decode(<<n::8, rest::binary>>), do: {:ok, {n, rest}}
  def decode(<<>>), do: {:error, "empty input"}
  def decode(_), do: {:error, "insufficient data"}
end
