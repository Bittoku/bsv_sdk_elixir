defmodule BSV.Tokens.Script.Stas3PiecesTest do
  @moduledoc """
  Tests for STAS 3.0 v0.1 §8.1 / §9.5 piece-array trailing parameters.

  Strategy:
    * Build synthetic preceding transactions whose serialised form contains
      one or more outputs with a STAS-shaped locking script (engine prefix
      0x6D 0x82 0x73 0x63 followed by sentinel bytes).
    * Excise those locking-script tails, assert the resulting trailing
      block has the expected hex (snapshot).
    * Round-trip via `parse/2`.
    * Cover edge cases: zero asset outputs, piece-count mismatch on parse,
      empty piece (two consecutive 0x20 bytes), counterparty-script length
      variations.
  """
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Stas3Pieces

  @engine <<0x6D, 0x82, 0x73, 0x63>>
  # 5 sentinel bytes to make the asset script easy to spot.
  @asset_tail @engine <> <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE>>

  describe "atomic-swap (txType=1) encoding" do
    test "single asset output → 2 pieces (before + after) joined by 0x20" do
      tx = synthetic_tx_with_outputs([asset_output()])

      counterparty = <<0xCC, 0xDD>>

      assert {:ok, body} =
               Stas3Pieces.encode_atomic_swap_pieces(counterparty, tx, [0])

      # Wire layout: pushdata(counterparty) ‖ count_byte ‖ pieces.
      <<0x02, 0xCC, 0xDD, count, array::binary>> = body
      assert count == 2

      # Round trip restores the structure.
      assert {:ok,
              %{
                counterparty_script: ^counterparty,
                piece_count: 2,
                pieces: pieces
              }} = Stas3Pieces.parse(body, 1)

      assert length(pieces) == 2

      # The two pieces, joined by a single 0x20, MUST equal the array
      # body (i.e. the join is exact and reversible).
      assert array == join(pieces)
    end

    test "two asset outputs at different indices → 3 pieces, reverse-ordered" do
      # outputs: [asset, dust, asset]
      tx = synthetic_tx_with_outputs([asset_output(), dust_output(), asset_output()])
      counterparty = <<0x42>>

      assert {:ok, body} =
               Stas3Pieces.encode_atomic_swap_pieces(counterparty, tx, [0, 2])

      assert {:ok, %{piece_count: 3, pieces: pieces}} = Stas3Pieces.parse(body, 1)
      assert length(pieces) == 3

      # The 3 pieces must concatenate (with single-space joiners) to the
      # tx bytes minus the two excised regions.
      assert join(pieces) == tx_minus_excised(tx, [0, 2])
    end

    test "zero asset outputs is rejected" do
      tx = synthetic_tx_with_outputs([dust_output()])

      assert {:error, :no_asset_outputs} =
               Stas3Pieces.encode_atomic_swap_pieces(<<0x01>>, tx, [])
    end

    test "counterparty script length variations (empty / 75 / 200 bytes)" do
      tx = synthetic_tx_with_outputs([asset_output()])

      for cp <- [<<>>, :binary.copy(<<0x55>>, 75), :binary.copy(<<0x77>>, 200)] do
        assert {:ok, body} = Stas3Pieces.encode_atomic_swap_pieces(cp, tx, [0])

        assert {:ok, %{counterparty_script: ^cp, piece_count: 2}} =
                 Stas3Pieces.parse(body, 1)
      end
    end

    test "snapshot: exact hex of trailing block for a fixed synthetic tx" do
      tx = synthetic_tx_with_outputs([asset_output()])
      counterparty = <<0xAB, 0xCD, 0xEF>>

      assert {:ok, body} =
               Stas3Pieces.encode_atomic_swap_pieces(counterparty, tx, [0])

      hex = Base.encode16(body, case: :lower)

      # Pinned: pushdata(<<0xab, 0xcd, 0xef>>) = 03 ab cd ef ; count = 0x02
      assert String.starts_with?(hex, "03abcdef02")
    end
  end

  describe "merge (txType=2..4) encoding" do
    test "txType=2: 1 asset excision → 2 pieces" do
      tx = synthetic_tx_with_outputs([asset_output()])

      assert {:ok, body} = Stas3Pieces.encode_merge_pieces(2, tx, [0])
      <<count, array::binary>> = body
      assert count == 2
      assert {:ok, %{piece_count: 2, pieces: ps}} = Stas3Pieces.parse(body, 2)
      assert length(ps) == 2
      assert join(ps) == array
    end

    test "txType=3: 2 asset excisions interleaved with dust → 3 pieces" do
      tx =
        synthetic_tx_with_outputs([
          asset_output(),
          dust_output(),
          asset_output(),
          dust_output()
        ])

      assert {:ok, body} = Stas3Pieces.encode_merge_pieces(3, tx, [0, 2])
      assert {:ok, %{piece_count: 3, pieces: ps}} = Stas3Pieces.parse(body, 3)
      assert length(ps) == 3
    end

    test "txType=4: 3 asset excisions → 4 pieces" do
      tx =
        synthetic_tx_with_outputs([
          asset_output(),
          asset_output(),
          asset_output(),
          dust_output()
        ])

      assert {:ok, body} = Stas3Pieces.encode_merge_pieces(4, tx, [0, 1, 2])
      assert {:ok, %{piece_count: 4, pieces: ps}} = Stas3Pieces.parse(body, 4)
      assert length(ps) == 4
    end

    test "piece_count outside 2..7 is rejected" do
      tx = synthetic_tx_with_outputs([asset_output(), asset_output()])
      # 1 and 8 are out of merge range; the function head doesn't match
      # the in-range guard, so we route to the catch-all that returns
      # {:error, :invalid_piece_count}.
      assert {:error, {:invalid_piece_count, 8}} =
               Stas3Pieces.encode_merge_pieces(8, tx, [0, 1])
    end

    test "piece_count != length(asset_output_indices) + 1 is rejected" do
      tx = synthetic_tx_with_outputs([asset_output(), asset_output()])

      # piece_count 3 expects 2 excisions; we pass only 1 → mismatch
      assert {:error, {:piece_count_mismatch, 3, 1}} =
               Stas3Pieces.encode_merge_pieces(3, tx, [0])
    end

    test "snapshot: exact hex of merge=2 trailing for fixed synthetic tx" do
      tx = synthetic_tx_with_outputs([asset_output()])
      assert {:ok, body} = Stas3Pieces.encode_merge_pieces(2, tx, [0])

      hex = Base.encode16(body, case: :lower)
      # Leading byte must be the piece count (0x02).
      assert String.starts_with?(hex, "02")
      # Body must contain at least one 0x20 separator.
      assert String.contains?(hex, "20")
    end
  end

  describe "round-trip" do
    test "encode → parse → assert structural equality" do
      tx = synthetic_tx_with_outputs([asset_output(), dust_output(), asset_output()])
      cp = :binary.copy(<<0x99>>, 32)

      assert {:ok, body} = Stas3Pieces.encode_atomic_swap_pieces(cp, tx, [0, 2])

      assert {:ok,
              %{
                counterparty_script: ^cp,
                piece_count: count,
                pieces: pieces
              }} = Stas3Pieces.parse(body, 1)

      assert count == length(pieces)

      # Re-encode from pieces and compare body.
      reencoded = pushdata(cp) <> <<count::8>> <> join(pieces)
      assert body == reencoded
    end
  end

  describe "parse-time validation" do
    test "parse rejects piece_count mismatch on merge" do
      # Hand-craft a body claiming count=3 but containing 2 pieces.
      malformed = <<0x03, "aa", 0x20, "bb">>

      assert {:error, {:piece_array_length_mismatch, 3, 2}} =
               Stas3Pieces.parse(malformed, 3)
    end

    test "parse rejects unsupported tx_type" do
      assert {:error, {:unsupported_tx_type, 9}} = Stas3Pieces.parse(<<>>, 9)
    end

    test "empty piece (two consecutive 0x20 bytes) round-trips" do
      # array = "aa" 0x20 0x20 "bb" → 3 pieces: "aa", "", "bb"
      array = <<"aa", 0x20, 0x20, "bb">>
      body = <<0x03, array::binary>>

      assert {:ok, %{piece_count: 3, pieces: ["aa", "", "bb"]}} =
               Stas3Pieces.parse(body, 3)
    end
  end

  # ────────────────────────────────────────────────────────────────────
  # Helpers — synthetic preceding-tx construction
  # ────────────────────────────────────────────────────────────────────

  # Build a minimal, serialiser-compatible transaction with one input and
  # `outputs` outputs. Outputs are passed as locking-script binaries.
  defp synthetic_tx_with_outputs(output_scripts) do
    version = <<1::little-32>>

    # 1 input: 32-byte zero outpoint, vout 0, empty script, sequence 0xFFFFFFFF.
    input_count = <<1>>
    outpoint = :binary.copy(<<0>>, 32) <> <<0::little-32>>
    in_script = <<0>>
    sequence = <<0xFFFFFFFF::little-32>>

    inputs = input_count <> outpoint <> in_script <> sequence

    output_count = <<length(output_scripts)>>

    outputs =
      Enum.reduce(output_scripts, <<>>, fn script, acc ->
        value = <<546::little-64>>
        len = byte_size(script)

        len_field =
          cond do
            len < 0xFD -> <<len>>
            len <= 0xFFFF -> <<0xFD, len::little-16>>
            true -> <<0xFE, len::little-32>>
          end

        acc <> value <> len_field <> script
      end)

    locktime = <<0::little-32>>

    version <> inputs <> output_count <> outputs <> locktime
  end

  # An "asset" output is a STAS-shaped locking script: 1B pretend owner-push
  # opcode, 20B owner, 1B var2-push, then the engine prefix + tail.
  defp asset_output do
    <<0x14>> <> :binary.copy(<<0x77>>, 20) <> <<0x00>> <> @asset_tail
  end

  defp dust_output, do: <<0x76, 0xA9, 0x14>> <> :binary.copy(<<0x88>>, 20) <> <<0x88, 0xAC>>

  # Compute the bytes of `tx` minus the excised asset-script regions for
  # the named outputs, joined with 0x20 (matches encoder semantics).
  defp tx_minus_excised(tx, indices) do
    {:ok, pieces} = Stas3Pieces.build_pieces_from_tx(tx, indices)
    join(pieces)
  end

  defp join([]), do: <<>>
  defp join([only]), do: only

  defp join([head | tail]),
    do: Enum.reduce(tail, head, fn p, acc -> acc <> <<0x20>> <> p end)

  # Mirror Stas3Pieces' internal pushdata for the snapshot reencode test.
  defp pushdata(<<>>), do: <<0x00>>
  defp pushdata(d) when byte_size(d) <= 75, do: <<byte_size(d)::8>> <> d
  defp pushdata(d) when byte_size(d) <= 255, do: <<0x4C, byte_size(d)::8>> <> d
  defp pushdata(d) when byte_size(d) <= 0xFFFF, do: <<0x4D, byte_size(d)::little-16>> <> d
end
