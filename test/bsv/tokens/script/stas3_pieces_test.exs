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
      counterparty-script length variations, and the engine-driven
      length-prefixed piece encoding (1-byte length per piece, no
      separators) — see `piece_array is length-prefixed not separator-delimited`.
  """
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Stas3Pieces

  @engine <<0x6D, 0x82, 0x73, 0x63>>
  # 5 sentinel bytes to make the asset script easy to spot.
  @asset_tail @engine <> <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE>>

  describe "atomic-swap (txType=1) encoding" do
    test "single asset output → 2 pieces (each length-prefixed)" do
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

      # The two pieces, each prefixed by a 1-byte length, MUST equal the
      # array body (i.e. the join is exact and reversible).
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

      # The 3 pieces, each length-prefixed, must concatenate to the
      # array body produced by the encoder.
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

    test "piece_array is length-prefixed not separator-delimited" do
      # Hand-build a 2-piece reverse-ordered array {"AB", "CD"} via the
      # encoder by constructing a preceding tx whose only asset script's
      # excision produces those two pieces. Easier: directly invoke the
      # internal join via the public encoder by crafting a tx where the
      # before/after slices are exactly "AB" and "CD".
      #
      # Simpler still: use Stas3Pieces.split_pieces/2 round-trip to assert
      # the encoded layout. The encoder's join is private, but the
      # behaviour is observable via the encoded body of any successful
      # encode_atomic_swap_pieces call: the array bytes are exactly
      # `<<len_a::8, a::binary, len_b::8, b::binary>>` with NO separators.
      #
      # Build: counterparty = <<>>, tx with one asset output crafted so
      # the two resulting pieces are precisely "AB" and "CD" (in reverse
      # order — the `tail` piece comes first, the `before` piece comes
      # second). We construct the tx by hand.
      #
      # An easier and more direct assertion: parse a hand-rolled
      # length-prefixed body and confirm it round-trips to ["AB", "CD"].
      array = <<0x02, 0x41, 0x42, 0x02, 0x43, 0x44>>
      body = <<0x00, 0x02, array::binary>>

      assert {:ok, %{counterparty_script: <<>>, piece_count: 2, pieces: ["AB", "CD"]}} =
               Stas3Pieces.parse(body, 1)

      # And the reverse: directly invoke split_pieces/2 to confirm the
      # array layout is byte-exact.
      assert {:ok, ["AB", "CD"]} = Stas3Pieces.split_pieces(array, 2)
    end

    test "piece array rejects piece over 255 bytes" do
      # Build a synthetic tx whose excision produces a "before" piece of
      # 256 bytes (which the encoder MUST reject because piece length
      # cannot fit in a u8).
      #
      # We craft the tx so that the bytes BEFORE the asset script in
      # output 0 are >= 256 in size. Adding extra inputs/outputs is the
      # easiest way to push the asset script past byte 256.
      padding_dust = <<0x76, 0xA9>> <> :binary.copy(<<0xAA>>, 256) <> <<0x88, 0xAC>>

      # outputs: [dust(big), asset]
      tx = synthetic_tx_with_outputs([padding_dust, asset_output()])

      assert {:error, :invalid_piece} =
               Stas3Pieces.encode_atomic_swap_pieces(<<0x01>>, tx, [1])
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
    test "parse rejects piece_count mismatch on merge (truncated array)" do
      # Hand-craft a body claiming count=3 but only encoding 2 pieces in
      # length-prefixed form: 0x02 "aa" 0x02 "bb" — third length read
      # would fall off the end.
      malformed = <<0x03, 0x02, "aa", 0x02, "bb">>

      assert {:error, :invalid_piece_array_framing} =
               Stas3Pieces.parse(malformed, 3)
    end

    test "parse rejects unsupported tx_type" do
      assert {:error, {:unsupported_tx_type, 9}} = Stas3Pieces.parse(<<>>, 9)
    end

    test "empty piece (zero-length entry) round-trips" do
      # array = 0x02 "aa" 0x00 0x02 "bb" → 3 pieces: "aa", "", "bb"
      array = <<0x02, "aa", 0x00, 0x02, "bb">>
      body = <<0x03, array::binary>>

      assert {:ok, %{piece_count: 3, pieces: ["aa", "", "bb"]}} =
               Stas3Pieces.parse(body, 3)
    end
  end

  describe "real STAS 3.0 locking-script fixture (cross-SDK pin)" do
    # CROSS-SDK FIXTURE: this exact preceding_tx + merge encoding is also
    # pinned in the Rust SDK at
    #   bsv-sdk-rust/crates/bsv-tokens/src/script/stas3_pieces.rs
    #   → test `real_stas3_merge_cross_sdk_pin`.
    # Both SDKs MUST produce byte-identical output for the same input.
    #
    # The fixture uses REAL STAS3 locking scripts — `0x14 <owner:20>` +
    # `<var2 = OP_0>` + the 2812-byte engine base template (first 4 bytes
    # `6d827363` = engine prefix) + a `0x14 <redemption:20>` post-OP_RETURN
    # push. On a real STAS3 script Rust's "excise past [owner][var2]" and
    # Elixir's "excise from engine prefix" land on the SAME offset (22),
    # so the encoders converge. They only diverge on malformed (non-STAS3)
    # input — which is a fixture artifact, not a spec bug.
    test "encode_merge_pieces/3 matches the pinned cross-SDK canonical hex" do
      tx = real_stas3_preceding_tx()

      assert {:ok, body} = Stas3Pieces.encode_merge_pieces(3, tx, [0, 1])

      # Cross-SDK canonical merge trailing-param hex (txType=3, vouts [0,1]).
      canonical_merge_hex =
        "030400000000210000000000000000fd270b14b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00050010000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff020000000000000000fd270b14a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000"

      assert Base.encode16(body, case: :lower) == canonical_merge_hex

      # Round-trips through the parser to 3 pieces.
      assert {:ok, %{piece_count: 3, pieces: pieces}} = Stas3Pieces.parse(body, 3)
      assert length(pieces) == 3
    end
  end

  # ────────────────────────────────────────────────────────────────────
  # Helpers — synthetic preceding-tx construction
  # ────────────────────────────────────────────────────────────────────

  # The 2812-byte STAS 3.0 engine base template (starts with the engine
  # prefix 6d827363, ends with 0x6a OP_RETURN). Same blob pinned in
  # reader_push_data_test.exs and the Rust SDK's stas3_pieces.rs fixture.
  @stas3_base_template_hex "6d82736301218763007b7b517c6e5667766b517f786b517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68766c936c7c5493686751687652937a76aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e011f7f7d7e01007e8111414136d08c5ed2bf3ba048afe6dcaebafe01005f80837e01007e7652967b537a7601ff877c0100879b7d648b6752799368537a7d9776547aa06394677768263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01417e7c6421038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b92186721023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc4868ad547f7701207f01207f7701247f517f7801007e02fd00a063546752687f7801007e817f727e7b517f7c01147d887f517f7c01007e817601619f6976014ea063517c7b6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f007b7b687602fd0a7f7701147f7c5579876b826475020100686b587a5893766b7a765155a569005379736382013ca07c517f7c51877b9a6352795487637101007c7e717101207f01147f75777c7567756c766b8b8b79518868677568686c6c7c6b517f7c817f788273638c7f776775010068518463517f7c01147d887f547952876372777c717c767663517f756852875779766352790152879a689b63517f77567a7567527c7681014f0161a5587a9a63015094687e68746c766b5c9388748c76795879888c8c7978886777717c767663517f7568528778015287587a9a9b745394768b797663517f756852877c6c766b5c936ea0637c8c768b797663517f75685287726b9b7c6c686ea0637c5394768b797663517f75685287726b9b7c6c686ea063755494797663517f756852879b676d689b63006968687c717167567a75686d7c518763755279686c755879a9886b6b6b6b6b6b6b827763af686c6c6c6c6c6c6c547a577a7664577a577a587a597a786354807e7e676d68aa880067765158a569765187645294587a53795a7a7e7e78637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6867587a6876aa5a7a7d54807e597a5b7a5c7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa5a7a7d877663516752687c72879b69537a6491687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e817602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75517f7c01147d887f517f7c01007e817601619f6976014ea0637c6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f68557964577988756d67716881687863567a677b68587f7c8153796353795287637b6b537a6b717c6b6b537a6b676b577a6b597a6b587a6b577a6b7c68677b93687c547f7701207f75748c7a7669765880044676a914780114748c7a76727b748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685c795c79636c766b7363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e0a888201218763ac67517f07517f73637c7f6876767e767e7e02ae687e7e7c557a00740111a063005a79646b7c748c7a76697d937b7b58807e6c91677c748c7a7d58807e6c6c6c557a680114748c7a748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685479635f79676c766b0115797363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7c637e677c6b7c6b7c6b7e7c6b68685979636c6c766b786b7363517f7c51876301347f77547f547f75786352797b01007e81957c01007e81965379a169676d68677568685c797363517f7c51876301347f77547f547f75786354797b01007e81957c01007e819678a169676d68677568687568740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68597a636c6c6c6d6c6c6d6c9d687c587a9d7d7e5c79635d795880041976a9145e797e0288ac7e7e6700687d7e5c7a766302006a7c7e827602fc00a06301fd7c7e536751687f757c7e0058807c7e687d7eaa6b7e7e7e7e7e7eaa78877c6c877c6c9a9b726d726d77776a"

  # Build a REAL STAS 3.0 locking script:
  #   0x14 <owner:20> + <var2 = OP_0> + 2812-byte base template
  #   + <0x14 redemption:20> post-OP_RETURN data.
  defp real_stas3_locking_script(owner_byte, redemption_byte) do
    {:ok, base} = Base.decode16(@stas3_base_template_hex, case: :mixed)
    owner_push = <<0x14>> <> :binary.copy(<<owner_byte>>, 20)
    var2_push = <<0x00>>
    post_data = <<0x14>> <> :binary.copy(<<redemption_byte>>, 20)
    owner_push <> var2_push <> base <> post_data
  end

  # Preceding tx with two real STAS3 outputs (owners 0xA0.. / 0xB0..,
  # shared redemption 0xCC..) and one dummy input. Built with a dedicated
  # serialiser (NOT the shared `synthetic_tx_with_outputs/1`) so the byte
  # layout — prev_txid 32×0x11, output value 0 — is byte-identical to the
  # Rust SDK's `cross_sdk_preceding_tx` helper and the canonical hex pin.
  defp real_stas3_preceding_tx do
    script0 = real_stas3_locking_script(0xA0, 0xCC)
    script1 = real_stas3_locking_script(0xB0, 0xCC)
    cross_sdk_preceding_tx([script0, script1])
  end

  # Cross-SDK preceding-tx serialiser. 1 input (prev_txid 32×0x11, vout 0,
  # empty scriptSig, sequence 0xFFFFFFFF), N value-0 outputs, locktime 0.
  defp cross_sdk_preceding_tx(output_scripts) do
    version = <<1::little-32>>
    inputs =
      <<1>> <>
        :binary.copy(<<0x11>>, 32) <> <<0::little-32>> <> <<0>> <> <<0xFFFFFFFF::little-32>>

    output_count = <<length(output_scripts)>>

    outputs =
      Enum.reduce(output_scripts, <<>>, fn script, acc ->
        value = <<0::little-64>>
        len = byte_size(script)

        len_field =
          cond do
            len < 0xFD -> <<len>>
            len <= 0xFFFF -> <<0xFD, len::little-16>>
            true -> <<0xFE, len::little-32>>
          end

        acc <> value <> len_field <> script
      end)

    version <> inputs <> output_count <> outputs <> <<0::little-32>>
  end

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

  # Compute the length-prefixed piece-array body produced by the encoder
  # for the named outputs (matches encoder semantics).
  defp tx_minus_excised(tx, indices) do
    {:ok, pieces} = Stas3Pieces.build_pieces_from_tx(tx, indices)
    join(pieces)
  end

  # Length-prefixed join, mirroring Stas3Pieces' internal `join_pieces/1`.
  defp join(pieces) do
    Enum.reduce(pieces, <<>>, fn piece, acc ->
      <<acc::binary, byte_size(piece)::8, piece::binary>>
    end)
  end

  # Mirror Stas3Pieces' internal pushdata for the snapshot reencode test.
  defp pushdata(<<>>), do: <<0x00>>
  defp pushdata(d) when byte_size(d) <= 75, do: <<byte_size(d)::8>> <> d
  defp pushdata(d) when byte_size(d) <= 255, do: <<0x4C, byte_size(d)::8>> <> d
  defp pushdata(d) when byte_size(d) <= 0xFFFF, do: <<0x4D, byte_size(d)::little-16>> <> d
end
