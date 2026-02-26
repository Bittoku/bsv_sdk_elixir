defmodule BSV.Script.ScriptNum do
  @moduledoc """
  Bitcoin script number encoding/decoding.

  Numbers are encoded as little-endian byte arrays with the sign bit
  in the MSB of the last byte.
  """

  import Bitwise

  @doc """
  Decode a binary script number to an integer.

  ## Examples

      iex> BSV.Script.ScriptNum.decode_num(<<>>)
      0

      iex> BSV.Script.ScriptNum.decode_num(<<0x81>>)
      -1
  """
  @spec decode_num(binary()) :: integer()
  # Note: negative zero (0x80) decodes to 0 per Bitcoin consensus rules.
  # The sign bit is cleared, yielding abs_val XOR mask == 0.
  def decode_num(<<>>), do: 0

  def decode_num(bin) when is_binary(bin) do
    bytes = :binary.bin_to_list(bin)
    last = List.last(bytes)
    negative = (last &&& 0x80) != 0

    # Build absolute value from little-endian
    abs_val =
      bytes
      |> Enum.with_index()
      |> Enum.reduce(0, fn {b, i}, acc ->
        acc ||| b <<< (8 * i)
      end)

    if negative do
      # Clear sign bit
      mask = 0x80 <<< (8 * (length(bytes) - 1))
      -bxor(abs_val, mask)
    else
      abs_val
    end
  end

  @doc """
  Encode an integer as a binary script number.

  ## Examples

      iex> BSV.Script.ScriptNum.encode_num(0)
      <<>>

      iex> BSV.Script.ScriptNum.encode_num(-1)
      <<0x81>>
  """
  @spec encode_num(integer()) :: binary()
  def encode_num(0), do: <<>>

  def encode_num(val) when is_integer(val) do
    negative = val < 0
    abs_val = abs(val)

    # Convert to little-endian bytes
    bytes = int_to_le_bytes(abs_val, [])

    # Handle sign bit
    last = List.last(bytes)

    bytes =
      if (last &&& 0x80) != 0 do
        # Need extra byte for sign
        bytes ++ [if(negative, do: 0x80, else: 0x00)]
      else
        if negative do
          List.update_at(bytes, length(bytes) - 1, &(&1 ||| 0x80))
        else
          bytes
        end
      end

    :binary.list_to_bin(bytes)
  end

  defp int_to_le_bytes(0, []), do: [0]
  defp int_to_le_bytes(0, acc), do: acc

  defp int_to_le_bytes(val, acc) do
    int_to_le_bytes(val >>> 8, acc ++ [val &&& 0xFF])
  end

  @doc "Check if a binary is minimally encoded as a script number."
  @spec minimally_encoded?(binary()) :: boolean()
  def minimally_encoded?(<<>>), do: true

  def minimally_encoded?(bin) when is_binary(bin) do
    last = :binary.last(bin)

    if (last &&& 0x7F) == 0 do
      if byte_size(bin) == 1 do
        false
      else
        prev = :binary.at(bin, byte_size(bin) - 2)
        (prev &&& 0x80) != 0
      end
    else
      true
    end
  end
end
