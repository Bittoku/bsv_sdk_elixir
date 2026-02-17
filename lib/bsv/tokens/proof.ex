defmodule BSV.Tokens.Proof do
  @moduledoc """
  Prev-TX split utility for Back-to-Genesis (BTG) proof system.

  Provides `split_tx_around_output/2`, which splits a raw serialized transaction
  into three byte segments around a specified output index. The spender pushes
  these three segments in the unlocking script so that the BTG locking script
  can reconstruct the previous transaction, verify its hash against the outpoint
  txid, and inspect the output's locking script for legitimacy.
  """

  alias BSV.Crypto

  @doc """
  Split a raw serialized transaction into three byte segments around the output
  at index `vout`.

  Returns `{:ok, {prefix, output_bytes, suffix}}` where:
    `hash256(prefix <> output_bytes <> suffix) == txid`

  The `output_bytes` segment contains the serialized output at `vout` in wire
  format: `satoshis(8 LE) + varint(script_len) + script_bytes`.
  """
  @spec split_tx_around_output(binary(), non_neg_integer()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, String.t()}
  def split_tx_around_output(raw_tx, vout) when is_binary(raw_tx) and is_integer(vout) do
    if byte_size(raw_tx) < 10 do
      {:error, "raw TX too short"}
    else
      with {:ok, cursor} <- skip_inputs(raw_tx, 4),
           {:ok, {output_count, cursor}} <- read_varint(raw_tx, cursor),
           :ok <- check_vout_range(vout, output_count),
           {:ok, {output_start, output_end}} <- find_output_boundaries(raw_tx, cursor, vout, output_count) do
        prefix = binary_part(raw_tx, 0, output_start)
        output_bytes = binary_part(raw_tx, output_start, output_end - output_start)
        suffix = binary_part(raw_tx, output_end, byte_size(raw_tx) - output_end)

        # Sanity check
        reconstructed = prefix <> output_bytes <> suffix
        if Crypto.sha256d(reconstructed) == Crypto.sha256d(raw_tx) do
          {:ok, {prefix, output_bytes, suffix}}
        else
          {:error, "internal error: reconstructed TX hash mismatch"}
        end
      end
    end
  end

  @doc """
  Read a Bitcoin varint from `data` at the given `offset`.

  Returns `{:ok, {value, new_offset}}` on success.
  """
  @spec read_varint(binary(), non_neg_integer()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}} | {:error, String.t()}
  def read_varint(data, offset) when is_binary(data) and is_integer(offset) do
    if offset >= byte_size(data) do
      {:error, "truncated varint"}
    else
      first = :binary.at(data, offset)

      case first do
        n when n <= 0xFC ->
          {:ok, {n, offset + 1}}

        0xFD ->
          if offset + 3 > byte_size(data) do
            {:error, "truncated varint (fd)"}
          else
            <<_::binary-size(offset + 1), value::little-16, _::binary>> = data
            {:ok, {value, offset + 3}}
          end

        0xFE ->
          if offset + 5 > byte_size(data) do
            {:error, "truncated varint (fe)"}
          else
            <<_::binary-size(offset + 1), value::little-32, _::binary>> = data
            {:ok, {value, offset + 5}}
          end

        0xFF ->
          if offset + 9 > byte_size(data) do
            {:error, "truncated varint (ff)"}
          else
            <<_::binary-size(offset + 1), value::little-64, _::binary>> = data
            {:ok, {value, offset + 9}}
          end
      end
    end
  end

  @doc """
  Encode a non-negative integer as a Bitcoin varint byte sequence.
  """
  @spec encode_varint(non_neg_integer()) :: binary()
  def encode_varint(value) when value < 0xFD, do: <<value::8>>
  def encode_varint(value) when value <= 0xFFFF, do: <<0xFD, value::little-16>>
  def encode_varint(value) when value <= 0xFFFFFFFF, do: <<0xFE, value::little-32>>
  def encode_varint(value), do: <<0xFF, value::little-64>>

  # ---- Private helpers ----

  defp skip_inputs(data, cursor) do
    tx_len = byte_size(data)

    with {:ok, {input_count, cursor}} <- read_varint(data, cursor) do
      skip_n_inputs(data, tx_len, cursor, input_count)
    end
  end

  defp skip_n_inputs(_data, _tx_len, cursor, 0), do: {:ok, cursor}

  defp skip_n_inputs(data, tx_len, cursor, remaining) do
    # prev_txid (32) + prev_vout (4)
    if cursor + 36 > tx_len do
      {:error, "truncated input"}
    else
      cursor = cursor + 36

      with {:ok, {script_len, cursor}} <- read_varint(data, cursor) do
        # script + sequence (4)
        if cursor + script_len + 4 > tx_len do
          {:error, "truncated input script"}
        else
          skip_n_inputs(data, tx_len, cursor + script_len + 4, remaining - 1)
        end
      end
    end
  end

  defp check_vout_range(vout, output_count) do
    if vout >= output_count do
      {:error, "vout #{vout} out of range (tx has #{output_count} outputs)"}
    else
      :ok
    end
  end

  defp find_output_boundaries(data, cursor, target_vout, output_count) do
    tx_len = byte_size(data)
    walk_outputs(data, tx_len, cursor, 0, target_vout, output_count, nil)
  end

  defp walk_outputs(_data, _tx_len, _cursor, idx, _target, count, result) when idx >= count do
    case result do
      nil -> {:error, "output not found"}
      {s, e} -> {:ok, {s, e}}
    end
  end

  defp walk_outputs(data, tx_len, cursor, idx, target, count, result) do
    output_start = cursor

    # satoshis (8 bytes)
    if cursor + 8 > tx_len do
      {:error, "truncated output satoshis"}
    else
      cursor = cursor + 8

      with {:ok, {script_len, cursor}} <- read_varint(data, cursor) do
        if cursor + script_len > tx_len do
          {:error, "truncated output script"}
        else
          cursor = cursor + script_len

          new_result =
            if idx == target, do: {output_start, cursor}, else: result

          walk_outputs(data, tx_len, cursor, idx + 1, target, count, new_result)
        end
      end
    end
  end
end
