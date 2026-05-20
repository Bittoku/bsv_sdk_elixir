defmodule BSV.Tokens.Script.Stas3Pieces do
  @moduledoc """
  STAS 3.0 v0.2.3 §8 / §9.5 atomic-swap and merge "piece array" trailing
  parameters for STAS 3.0 unlocking scripts.

  ## Background

  For atomic-swap (`txType = 1`) and merge transactions (`txType = 2..7`),
  the STAS unlocking script appends a trailing block whose layout depends
  on `txType`. Per spec v0.2.3, each piece is **its own
  `OP_PUSHDATA` operation** in the unlocking script, and `piece_count` is
  a **minimal Bitcoin numeric push** (DXS convention from
  `dxs-bsv-token-sdk`'s `ScriptBuilder.addNumber`: for `n ∈ 1..=16` emit
  `OP_<n>` = single byte `0x50 + n`; for `n ∈ 17..=127` emit `0x01 <n>`;
  for larger emit script-num-encoded with sign-bit sentinel):

      # txType = 1 (atomic swap)
      pushdata(counterparty_locking_script)
      minimal_numeric_push(piece_count)
      pushdata(piece_1) ... pushdata(piece_N)

      # txType = 2..7 (merge)
      minimal_numeric_push(piece_count)         # must equal txType
      pushdata(piece_1) ... pushdata(piece_N)

  ## What "pieces" are (spec §9.5)

  The canonical engine
  (`github.com/stassso/STAS-3-script-templates`) consumes them via an
  unrolled, counter-driven block:

      OP_OVER OP_IF OP_SWAP OP_1SUB OP_SWAP OP_3 OP_PICK OP_CAT OP_10 OP_ROLL OP_CAT OP_ENDIF

  repeated 5×, driven by a decrementing `piece_count` counter. There is
  **no concatenated length-prefixed blob** and **no per-piece size limit** —
  the earlier 127-byte limit was a phantom of the obsolete encoding.

  Given the preceding transaction (the tx that produced the input UTXO):

  1. For each named asset output (`asset_output_indices`), locate the
     locking script. Within that script, identify the "asset script" —
     the bytes from the engine prefix (`0x6D 0x82 0x73 0x63`) to the end
     of the script. Everything BEFORE that prefix belongs to the two var
     fields (`owner` push + `var2` push) and is NOT excised.
  2. The remaining tx bytes (parts that AREN'T excised) are the pieces:
     one before the first excised region, one between each pair, and one
     after the last.
  3. Reverse the piece order (head on top of stack).
  4. Concatenate independent pushdata pushes — no length prefix inside.

  This module exposes:

    * `encode_atomic_swap_pieces/3` — build the trailing block for txType=1
    * `encode_merge_pieces/3` — build the trailing block for txType=2..7
    * `parse/2` — decode a previously-encoded trailing block

  Strict boundaries: at least one asset output must be named, the merge
  piece count must be in `2..7`, and parsed `piece_count` must match the
  number of pieces read back.
  """

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

  Returns the byte sequence formed by appending independent Bitcoin
  pushdata operations:

      pushdata(counterparty_script) ‖ minimal_numeric_push(piece_count) ‖
      pushdata(piece_1) ‖ … ‖ pushdata(piece_N)

  ready to splice verbatim into an unlocking script.

  `asset_output_indices` MUST list at least one valid output index in
  `preceding_tx`.
  """
  @spec encode_atomic_swap_pieces(binary(), binary(), [non_neg_integer()]) ::
          {:ok, binary()} | {:error, term()}
  def encode_atomic_swap_pieces(counterparty_locking_script, preceding_tx, asset_output_indices)
      when is_binary(counterparty_locking_script) and is_binary(preceding_tx) and
             is_list(asset_output_indices) do
    with {:ok, pieces} <- build_pieces_from_tx(preceding_tx, asset_output_indices) do
      count = length(pieces)

      cond do
        count == 0 ->
          {:error, :no_asset_outputs}

        count > 255 ->
          {:error, {:piece_count_overflow, count}}

        true ->
          out =
            pushdata(counterparty_locking_script) <>
              minimal_numeric_push(count) <>
              concat_pushdata(pieces)

          {:ok, out}
      end
    end
  end

  @doc """
  Build the trailing-parameters block for a merge unlocking script
  (`txType = 2..7`).

  Returns the byte sequence:

      minimal_numeric_push(piece_count) ‖
      pushdata(piece_1) ‖ … ‖ pushdata(piece_N)

  Per spec §8, `piece_count` MUST equal the merge txType (2..7) and MUST
  equal the resulting number of pieces. With `K` excised asset-script
  regions in `preceding_tx`, the resulting array has `K + 1` pieces, so
  `length(asset_output_indices)` MUST equal `piece_count - 1`.
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
        with {:ok, pieces} <- build_pieces_from_tx(preceding_tx, asset_output_indices) do
          if length(pieces) != piece_count do
            {:error, {:piece_count_mismatch, piece_count, length(pieces)}}
          else
            out =
              minimal_numeric_push(piece_count) <>
                concat_pushdata(pieces)

            {:ok, out}
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
                then a minimal-numeric-push piece_count, then `piece_count`
                independent pushdata piece operations. Returns
                `{:ok, %{counterparty_script: _, piece_count: _, pieces: _}}`.

    * `2..7`  — merge: leading minimal-numeric-push piece_count (must
                equal `tx_type`), then `piece_count` independent pushdata
                piece operations. Returns
                `{:ok, %{piece_count: _, pieces: _}}`.

  On malformed input — bad framing, count mismatch with array length,
  unsupported `tx_type` — returns `{:error, reason}`.
  """
  @spec parse(binary(), 1..7) ::
          {:ok, parsed_swap() | parsed_merge()} | {:error, term()}
  def parse(bin, 1) when is_binary(bin) do
    with {:ok, cp_script, rest1} <- read_pushdata(bin),
         {:ok, count_body, rest2} <- read_pushdata(rest1),
         {:ok, count} <- numeric_body(count_body),
         {:ok, pieces, leftover} <- read_n_pushdata(rest2, count) do
      cond do
        leftover != <<>> ->
          {:error, :piece_array_trailing_bytes}

        true ->
          {:ok, %{counterparty_script: cp_script, piece_count: count, pieces: pieces}}
      end
    else
      :error -> {:error, :invalid_pushdata}
      {:error, _} = err -> err
    end
  end

  def parse(bin, tx_type)
      when is_binary(bin) and is_integer(tx_type) and tx_type in 2..7 do
    with {:ok, count_body, rest} <- read_pushdata(bin),
         {:ok, count} <- numeric_body(count_body),
         true <- count == tx_type or {:error, {:piece_count_mismatch, tx_type, count}},
         {:ok, pieces, leftover} <- read_n_pushdata(rest, count) do
      cond do
        leftover != <<>> ->
          {:error, :piece_array_trailing_bytes}

        true ->
          {:ok, %{piece_count: count, pieces: pieces}}
      end
    else
      :error -> {:error, :invalid_pushdata}
      {:error, _} = err -> err
      other -> {:error, other}
    end
  end

  def parse(_, tx_type), do: {:error, {:unsupported_tx_type, tx_type}}

  # ──────────────────────────────────────────────────────────────────────
  # Internals — preceding-tx walking
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
      # to in-tx order — which is what we have.
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
  # every output. A minimal serialiser-aware walker — enough to skip
  # version, input list, and find each output's locking-script offset.
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

  # ──────────────────────────────────────────────────────────────────────
  # Internals — Bitcoin pushdata framing
  # ──────────────────────────────────────────────────────────────────────

  # Standard Bitcoin pushdata framing, opcode chosen by size.
  defp pushdata(<<>>), do: <<0x00>>

  defp pushdata(data) when byte_size(data) <= 75,
    do: <<byte_size(data)::8, data::binary>>

  defp pushdata(data) when byte_size(data) <= 255,
    do: <<0x4C, byte_size(data)::8, data::binary>>

  defp pushdata(data) when byte_size(data) <= 0xFFFF,
    do: <<0x4D, byte_size(data)::little-16, data::binary>>

  defp pushdata(data),
    do: <<0x4E, byte_size(data)::little-32, data::binary>>

  defp concat_pushdata(pieces),
    do: Enum.reduce(pieces, <<>>, fn p, acc -> acc <> pushdata(p) end)

  # Minimal Bitcoin numeric push (DXS's `ScriptBuilder.addNumber` shape):
  #
  #   * `n == 0`         → `OP_0` (0x00)
  #   * `n ∈ 1..=16`     → single opcode `OP_<n>` (`0x50 + n`)
  #   * `n ∈ 17..=127`   → 2-byte direct push `0x01 <n>` (positive script-num)
  #   * `n ∈ 128..=255`  → 3-byte push `0x02 <n> 0x00` (sign-bit sentinel)
  #
  # The engine decrements this value via `OP_1SUB` and tests it via
  # `OP_OVER OP_IF` on each unrolled iteration of the piece consumer.
  defp minimal_numeric_push(0), do: <<0x00>>
  defp minimal_numeric_push(n) when n in 1..16, do: <<0x50 + n>>
  defp minimal_numeric_push(n) when n in 17..127, do: <<0x01, n>>
  defp minimal_numeric_push(n) when n in 128..255, do: <<0x02, n, 0x00>>

  # Read a single Bitcoin pushdata or numeric opcode. Numeric opcodes
  # `OP_1NEGATE` (0x4F) and `OP_1..OP_16` (0x51..0x60) return their
  # script-num body (so `piece_count` reads back uniformly).
  defp read_pushdata(<<>>), do: :error
  defp read_pushdata(<<0x00, rest::binary>>), do: {:ok, <<>>, rest}
  defp read_pushdata(<<0x4F, rest::binary>>), do: {:ok, <<0x81>>, rest}

  defp read_pushdata(<<op, rest::binary>>) when op >= 0x51 and op <= 0x60,
    do: {:ok, <<op - 0x50>>, rest}

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

  # Read exactly `n` pushdata operations in sequence, returning the list
  # and the leftover bytes. Caller is responsible for asserting that the
  # leftover is empty (or has the structure they expect).
  defp read_n_pushdata(bytes, 0), do: {:ok, [], bytes}

  defp read_n_pushdata(bytes, n) when n > 0 do
    with {:ok, piece, rest} <- read_pushdata(bytes),
         {:ok, more, tail} <- read_n_pushdata(rest, n - 1) do
      {:ok, [piece | more], tail}
    else
      :error -> {:error, :truncated_piece}
      {:error, _} = err -> err
    end
  end

  # Reduce a 1-byte numeric body to an integer in 0..255. Anything else
  # is rejected as a malformed piece_count.
  defp numeric_body(<<n>>), do: {:ok, n}
  defp numeric_body(_), do: {:error, :malformed_piece_count}
end
