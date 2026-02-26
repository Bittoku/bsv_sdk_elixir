defmodule BSV.Base58 do
  @moduledoc """
  Base58 and Base58Check encoding/decoding using the Bitcoin alphabet.
  """

  @alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @alphabet_list String.graphemes(@alphabet)
  @alphabet_map @alphabet_list |> Enum.with_index() |> Map.new()

  @doc "Encode binary to Base58 string."
  @spec encode(binary()) :: String.t()
  def encode(<<>>), do: ""

  def encode(binary) when is_binary(binary) do
    leading_zeros = count_leading_zeros(binary, 0)
    prefix = String.duplicate("1", leading_zeros)
    num = :binary.decode_unsigned(binary, :big)
    prefix <> encode_int(num, [])
  end

  @doc "Decode Base58 string to binary."
  @spec decode(String.t()) :: {:ok, binary()} | {:error, String.t()}
  def decode(""), do: {:ok, <<>>}

  def decode(string) when is_binary(string) do
    chars = String.graphemes(string)
    leading_ones = count_leading_ones(chars, 0)

    case decode_chars(chars) do
      {:ok, 0} ->
        {:ok, :binary.copy(<<0>>, leading_ones)}

      {:ok, num} ->
        bytes = :binary.encode_unsigned(num, :big)
        {:ok, :binary.copy(<<0>>, leading_ones) <> bytes}

      error ->
        error
    end
  end

  @doc "Decode Base58 string, raising on error."
  @spec decode!(String.t()) :: binary()
  def decode!(string) do
    case decode(string) do
      {:ok, bin} -> bin
      {:error, reason} -> raise ArgumentError, reason
    end
  end

  @doc "Base58Check encode with version byte."
  @spec check_encode(binary(), non_neg_integer()) :: String.t()
  def check_encode(payload, version_byte) when is_integer(version_byte) do
    data = <<version_byte::8, payload::binary>>
    checksum = BSV.Crypto.sha256d(data) |> binary_part(0, 4)
    encode(data <> checksum)
  end

  @doc "Base58Check decode, returning version byte and payload."
  @spec check_decode(String.t()) :: {:ok, {non_neg_integer(), binary()}} | {:error, String.t()}
  def check_decode(string) do
    with {:ok, bin} <- decode(string),
         true <- byte_size(bin) >= 5 || {:error, "too short"},
         payload_len = byte_size(bin) - 4,
         <<data::binary-size(payload_len), checksum::binary-size(4)>> = bin,
         computed = BSV.Crypto.sha256d(data) |> binary_part(0, 4),
         true <- BSV.Crypto.secure_compare(checksum, computed) || {:error, "invalid checksum"},
         <<version::8, payload::binary>> = data do
      {:ok, {version, payload}}
    else
      {:error, _} = err -> err
    end
  end

  @doc "Base58Check encode raw data (no version byte splitting). Appends 4-byte checksum."
  @spec check_encode_raw(binary()) :: String.t()
  def check_encode_raw(data) when is_binary(data) do
    checksum = BSV.Crypto.sha256d(data) |> binary_part(0, 4)
    encode(data <> checksum)
  end

  @doc "Base58Check decode raw data. Returns `{:ok, data}` or `{:error, reason}`."
  @spec check_decode_raw(String.t()) :: {:ok, binary()} | {:error, String.t()}
  def check_decode_raw(string) do
    with {:ok, bin} <- decode(string),
         true <- byte_size(bin) >= 5 || {:error, "too short"},
         data_len = byte_size(bin) - 4,
         <<data::binary-size(data_len), checksum::binary-size(4)>> = bin,
         computed = BSV.Crypto.sha256d(data) |> binary_part(0, 4),
         true <- BSV.Crypto.secure_compare(checksum, computed) || {:error, "invalid checksum"} do
      {:ok, data}
    else
      {:error, _} = err -> err
    end
  end

  @doc "Base58Check decode, raising on error."
  @spec check_decode!(String.t()) :: {non_neg_integer(), binary()}
  def check_decode!(string) do
    case check_decode(string) do
      {:ok, result} -> result
      {:error, reason} -> raise ArgumentError, reason
    end
  end

  defp count_leading_zeros(<<0, rest::binary>>, acc), do: count_leading_zeros(rest, acc + 1)
  defp count_leading_zeros(_, acc), do: acc

  defp count_leading_ones(["1" | rest], acc), do: count_leading_ones(rest, acc + 1)
  defp count_leading_ones(_, acc), do: acc

  defp encode_int(0, []), do: ""
  defp encode_int(0, acc), do: IO.iodata_to_binary(acc)

  defp encode_int(num, acc) do
    encode_int(div(num, 58), [Enum.at(@alphabet_list, rem(num, 58)) | acc])
  end

  defp decode_chars(chars) do
    Enum.reduce_while(chars, {:ok, 0}, fn char, {:ok, acc} ->
      case Map.fetch(@alphabet_map, char) do
        {:ok, val} -> {:cont, {:ok, acc * 58 + val}}
        :error -> {:halt, {:error, "invalid Base58 character: #{char}"}}
      end
    end)
  end
end
