defmodule BSV.Tokens.Script.Stas3Pieces do
  @moduledoc """
  STAS 3.0 v0.1 §8.1 / §9.5 atomic-swap and merge "piece array" trailing
  parameters for STAS 3.0 unlocking scripts.

  ## Background

  For atomic-swap (`txType = 1`) and merge transactions (`txType = 2..7`),
  the STAS unlocking script appends a trailing block whose layout depends
  on `txType`:

      # txType = 1 (atomic swap)
      counterparty_locking_script  ←  full locking script of the OTHER party's STAS UTXO
      piece_count                   ←  1-byte unsigned integer
      piece_array                   ←  pieces, SPACE-delimited (0x20)

      # txType = 2..7 (merge)
      piece_count                   ←  1-byte unsigned integer; value MUST equal txType
      piece_array                   ←  pieces, SPACE-delimited (0x20)

  ## What "pieces" are (spec §9.5)

  Quoting the spec verbatim:

  > "The reverse-ordered array of pieces that remain after excising the
  > counterparty asset script from its preceding transaction. The excised
  > script constitutes all the token data right after the two variable
  > parameters at the very start of the STAS script. The reverse-ordered
  > array of pieces is delimited by space (' ') character."

  Concretely, given the preceding transaction (the tx that produced the
  swap input UTXO):

  1. For each named asset output (`asset_output_indices`), locate the
     locking script. Within that script, identify the "asset script" —
     i.e. the bytes from the engine prefix (`0x6D 0x82 0x73 0x63`) all
     the way to the end of the script. Everything BEFORE that prefix
     belongs to the two var fields (`owner` push + `var2` push) of the
     STAS frame and is NOT excised.
  2. The remaining tx bytes (the parts that AREN'T the excised regions)
     are the pieces. They are split into contiguous slices: one before
     the first excised region, one between each pair of adjacent
     excised regions, and one after the last.
  3. Reverse the piece order.
  4. Join the reversed pieces with single `0x20` (space) bytes.

  This module exposes:

    * `encode_atomic_swap_pieces/3` — build the trailing block for txType=1
    * `encode_merge_pieces/3` — build the trailing block for txType=2..7
    * `parse/2` — decode a previously-encoded trailing block

  Strict boundaries are enforced: at least one asset output must be named,
  the merge piece count must be in `2..7`, the inner array piece count
  must equal the leading length byte, and pushes after the leading
  counterparty-script length use Bitcoin pushdata framing (so reading
  back is unambiguous).
  """

  @space 0x20
  @engine_prefix <<0x6D, 0x82, 0x73, 0x63>>

  @typedoc "Result of `parse/2` for a swap trailing block."
  @type parsed_swap :: %{
          counterparty_script: binary(),
          piece_count: non_neg_integer(),
          pieces: [binary()]
        }

  @typedoc "Result of `parse/2` for a merge trailing block."
  @type parsed_merge :: %{
          piece_count: 2..7,
          pieces: [binary()]
        }

  # ──────────────────────────────────────────────────────────────────────
  # Encoder API
  # ──────────────────────────────────────────────────────────────────────

  @doc """
  Build the trailing-parameters block for a `txType = 1` atomic-swap
  unlocking script.

  Returns the raw byte sequence:

      counterparty_script_push  ‖  piece_count_byte  ‖  piece_array

  where `piece_array` is the reverse-ordered, space-delimited result of
  excising every named asset script from `preceding_tx`.

  `asset_output_indices` MUST list at least one valid output index in
  `preceding_tx`.
  """
  @spec encode_atomic_swap_pieces(binary(), binary(), [non_neg_integer()]) ::
          {:ok, binary()} | {:error, term()}
  def encode_atomic_swap_pieces(counterparty_locking_script, preceding_tx, asset_output_indices)
      when is_binary(counterparty_locking_script) and is_binary(preceding_tx) and
             is_list(asset_output_indices) do
    with {:ok, pieces} <-
           build_pieces_from_tx(preceding_tx, asset_output_indices) do
      cp_push = pushdata(counterparty_locking_script)
      count = length(pieces)

      if count > 255 do
        {:error, {:piece_count_overflow, count}}
      else
        body = <<cp_push::binary, count::8, join_pieces(pieces)::binary>>
        {:ok, body}
      end
    end
  end

  @doc """
  Build the trailing-parameters block for a merge unlocking script
  (`txType = 2..7`).

  Returns:

      piece_count_byte  ‖  piece_array

  Per spec §8.1, `piece_count` MUST equal the merge txType (2..7) and
  MUST equal the resulting number of pieces in the array. With `K`
  excised asset-script regions in `preceding_tx`, the resulting array
  has `K + 1` pieces (the slice before the first excision, the slices
  between adjacent excisions, and the slice after the last). So
  `length(asset_output_indices)` MUST equal `piece_count - 1`.

  ## Examples

    * txType=2 with one asset excision → 2 pieces
    * txType=3 with two asset excisions → 3 pieces
    * txType=7 with six asset excisions → 7 pieces
  """
  @spec encode_merge_pieces(2..7, binary(), [non_neg_integer()]) ::
          {:ok, binary()} | {:error, term()}
  def encode_merge_pieces(piece_count, preceding_tx, asset_output_indices)
      when is_integer(piece_count) and piece_count in 2..7 and
             is_binary(preceding_tx) and is_list(asset_output_indices) do
    expected_excisions = piece_count - 1

    cond do
      length(asset_output_indices) != expected_excisions ->
        {:error, {:piece_count_mismatch, piece_count, length(asset_output_indices)}}

      true ->
        with {:ok, pieces} <-
               build_pieces_from_tx(preceding_tx, asset_output_indices) do
          if length(pieces) != piece_count do
            {:error, {:piece_count_mismatch, piece_count, length(pieces)}}
          else
            body = <<piece_count::8, join_pieces(pieces)::binary>>
            {:ok, body}
          end
        end
    end
  end

  def encode_merge_pieces(piece_count, _, _) when is_integer(piece_count),
    do: {:error, {:invalid_piece_count, piece_count}}

  # ──────────────────────────────────────────────────────────────────────
  # Parser API
  # ──────────────────────────────────────────────────────────────────────

  @doc """
  Parse a previously-encoded trailing parameter block.

  `tx_type` selects the layout:

    * `1`     — atomic swap: leading pushdata-framed counterparty script,
                then 1-byte count, then space-delimited piece array.
                Returns `{:ok, %{counterparty_script: _, piece_count: _,
                pieces: _}}`.

    * `2..7`  — merge: 1-byte count (must equal `tx_type`), then
                space-delimited piece array. Returns `{:ok, %{piece_count:
                _, pieces: _}}`.

  On malformed input — bad framing, count mismatch with array length,
  unsupported tx_type — returns `{:error, reason}`.
  """
  @spec parse(binary(), 1..7) ::
          {:ok, parsed_swap() | parsed_merge()} | {:error, term()}
  def parse(bin, 1) when is_binary(bin) do
    with {:ok, cp_script, rest} <- read_pushdata(bin),
         <<count::8, array::binary>> <- rest,
         {:ok, pieces} <- split_pieces(array, count) do
      {:ok,
       %{
         counterparty_script: cp_script,
         piece_count: count,
         pieces: pieces
       }}
    else
      :error -> {:error, :invalid_pushdata}
      <<>> -> {:error, :missing_piece_count}
      {:error, _} = err -> err
      _ -> {:error, :invalid_swap_trailing}
    end
  end

  def parse(<<count::8, array::binary>>, tx_type)
      when is_integer(tx_type) and tx_type in 2..7 do
    cond do
      count != tx_type ->
        {:error, {:piece_count_mismatch, tx_type, count}}

      true ->
        case split_pieces(array, count) do
          {:ok, pieces} -> {:ok, %{piece_count: count, pieces: pieces}}
          {:error, _} = err -> err
        end
    end
  end

  def parse(_, tx_type), do: {:error, {:unsupported_tx_type, tx_type}}

  # ──────────────────────────────────────────────────────────────────────
  # Internals
  # ──────────────────────────────────────────────────────────────────────

  # Build the reverse-ordered piece list from the preceding tx and a
  # list of asset output indices. The "asset script" excised from each
  # named output is the locking-script slice from the engine prefix
  # (0x6D 0x82 0x73 0x63) onwards.
  @doc false
  @spec build_pieces_from_tx(binary(), [non_neg_integer()]) ::
          {:ok, [binary()]} | {:error, term()}
  def build_pieces_from_tx(_preceding_tx, []),
    do: {:error, :no_asset_outputs}

  def build_pieces_from_tx(preceding_tx, asset_output_indices) do
    with {:ok, ranges} <-
           collect_asset_script_ranges(preceding_tx, asset_output_indices) do
      tx_size = byte_size(preceding_tx)
      sorted = Enum.sort_by(ranges, fn {start, _len} -> start end)

      pieces =
        sorted
        |> Enum.reduce({[], 0}, fn {start, len}, {acc, cursor} ->
          piece = binary_part(preceding_tx, cursor, start - cursor)
          {[piece | acc], start + len}
        end)
        |> then(fn {acc, cursor} ->
          tail = binary_part(preceding_tx, cursor, tx_size - cursor)
          [tail | acc]
        end)

      # `acc` is already reversed (insertion order: first piece pushed
      # last). The spec says the array MUST be reverse-ordered relative
      # to in-tx order — which is exactly what we have.
      {:ok, pieces}
    end
  end

  # For each requested vout index, find its locking script's "engine
  # prefix" offset within the preceding tx and report the {start, length}
  # of the bytes from that offset to the end of the locking script.
  defp collect_asset_script_ranges(tx, indices) do
    with {:ok, output_locations} <- locate_outputs(tx) do
      Enum.reduce_while(indices, {:ok, []}, fn vout, {:ok, acc} ->
        case Enum.at(output_locations, vout) do
          nil ->
            {:halt, {:error, {:vout_out_of_range, vout}}}

          {script_start, script_len} ->
            script_bytes = binary_part(tx, script_start, script_len)

            case :binary.match(script_bytes, @engine_prefix) do
              :nomatch ->
                {:halt, {:error, {:engine_prefix_not_found, vout}}}

              {prefix_offset, _} ->
                excise_start = script_start + prefix_offset
                excise_len = script_len - prefix_offset
                {:cont, {:ok, [{excise_start, excise_len} | acc]}}
            end
        end
      end)
    end
  end

  # Walk the tx once, returning {script_start_offset, script_length} for
  # every output. We only need a minimal serialiser-aware walker — enough
  # to skip version, input list, and find each output's locking-script
  # offset.
  defp locate_outputs(tx) do
    try do
      <<_version::little-32, rest::binary>> = tx
      {input_count, rest, in_off} = read_varint(rest, 4)
      {rest, after_inputs_off} = skip_inputs(rest, input_count, in_off)
      {output_count, rest, out_off} = read_varint(rest, after_inputs_off)
      {locations, _} = collect_output_locations(rest, output_count, out_off, [])
      {:ok, Enum.reverse(locations)}
    rescue
      _ -> {:error, :malformed_preceding_tx}
    end
  end

  defp skip_inputs(rest, 0, off), do: {rest, off}

  defp skip_inputs(rest, n, off) do
    <<_outpoint::binary-size(36), rest1::binary>> = rest
    {script_len, rest2, after_len} = read_varint(rest1, off + 36)
    <<_unlock::binary-size(script_len), _seq::binary-size(4), rest3::binary>> = rest2
    skip_inputs(rest3, n - 1, after_len + script_len + 4)
  end

  defp collect_output_locations(rest, 0, off, acc), do: {acc, {rest, off}}

  defp collect_output_locations(rest, n, off, acc) do
    <<_value::little-64, rest1::binary>> = rest
    after_value_off = off + 8
    {script_len, rest2, after_len_off} = read_varint(rest1, after_value_off)
    script_start = after_len_off
    <<_script::binary-size(script_len), rest3::binary>> = rest2

    collect_output_locations(
      rest3,
      n - 1,
      after_len_off + script_len,
      [{script_start, script_len} | acc]
    )
  end

  # Bitcoin VarInt reader. Returns `{value, remaining_bytes, new_absolute_offset}`.
  defp read_varint(<<x, rest::binary>>, off) when x < 0xFD, do: {x, rest, off + 1}

  defp read_varint(<<0xFD, v::little-16, rest::binary>>, off),
    do: {v, rest, off + 3}

  defp read_varint(<<0xFE, v::little-32, rest::binary>>, off),
    do: {v, rest, off + 5}

  defp read_varint(<<0xFF, v::little-64, rest::binary>>, off),
    do: {v, rest, off + 9}

  # Bitcoin pushdata frame for the leading counterparty-script slot.
  # We mirror the conventions used in `Stas3Builder.push_data/1`.
  defp pushdata(<<>>), do: <<0x00>>

  defp pushdata(data) when byte_size(data) <= 75,
    do: <<byte_size(data)::8, data::binary>>

  defp pushdata(data) when byte_size(data) <= 255,
    do: <<0x4C, byte_size(data)::8, data::binary>>

  defp pushdata(data) when byte_size(data) <= 0xFFFF,
    do: <<0x4D, byte_size(data)::little-16, data::binary>>

  defp pushdata(data),
    do: <<0x4E, byte_size(data)::little-32, data::binary>>

  defp read_pushdata(<<0x00, rest::binary>>), do: {:ok, <<>>, rest}

  defp read_pushdata(<<len, data::binary-size(len), rest::binary>>)
       when len >= 0x01 and len <= 0x4B,
       do: {:ok, data, rest}

  defp read_pushdata(<<0x4C, len, data::binary-size(len), rest::binary>>),
    do: {:ok, data, rest}

  defp read_pushdata(<<0x4D, len::little-16, data::binary-size(len), rest::binary>>),
    do: {:ok, data, rest}

  defp read_pushdata(<<0x4E, len::little-32, data::binary-size(len), rest::binary>>),
    do: {:ok, data, rest}

  defp read_pushdata(_), do: :error

  # Join pieces with a single 0x20 separator BETWEEN consecutive pieces.
  defp join_pieces([]), do: <<>>
  defp join_pieces([single]), do: single

  defp join_pieces([head | tail]),
    do: Enum.reduce(tail, head, fn piece, acc -> <<acc::binary, @space, piece::binary>> end)

  # Split a joined byte run into exactly `expected_count` pieces, splitting
  # on every 0x20 byte. Empty pieces are allowed (two consecutive 0x20
  # bytes → empty middle piece).
  @doc false
  @spec split_pieces(binary(), non_neg_integer()) ::
          {:ok, [binary()]} | {:error, term()}
  def split_pieces(_array, 0), do: {:error, :zero_piece_count}

  def split_pieces(array, expected_count) when is_binary(array) do
    pieces =
      if expected_count == 1 do
        [array]
      else
        :binary.split(array, <<@space>>, [:global])
      end

    cond do
      length(pieces) == expected_count ->
        {:ok, pieces}

      true ->
        {:error, {:piece_array_length_mismatch, expected_count, length(pieces)}}
    end
  end
end
