defmodule BSV.Tokens.Script.TemplatesTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Templates
  alias BSV.Transaction.P2MPKH
  alias BSV.Crypto

  test "stas_v2_prefix" do
    assert Templates.stas_v2_prefix() == <<0x76, 0xA9, 0x14>>
  end

  test "stas_v2_marker" do
    assert Templates.stas_v2_marker() == <<0x88, 0xAC, 0x69, 0x76, 0xAA, 0x60>>
  end

  test "stas_v2 constants" do
    assert Templates.stas_v2_owner_offset() == 3
    assert Templates.pkh_len() == 20
    assert Templates.stas_v2_marker_offset() == 23
    assert Templates.stas_v2_template_len() == 1431
    assert Templates.stas_v2_op_return_offset() == 1409
    assert Templates.stas_v2_redemption_offset() == 1411
    assert Templates.stas_v2_min_len() == 1432
  end

  test "stas3 constants" do
    assert Templates.stas3_base_prefix() == <<0x6D, 0x82, 0x73, 0x63>>
    assert Templates.stas3_base_template_len() == 2812
  end

  test "p2pkh constants" do
    assert Templates.p2pkh_len() == 25
    assert Templates.p2pkh_prefix() == <<0x76, 0xA9, 0x14>>
    assert Templates.p2pkh_suffix() == <<0x88, 0xAC>>
  end

  describe "p2mpkh_locking_script/1 (STAS 3.0 v0.1 §10.2 fixed 70-byte body)" do
    test "is exactly 70 bytes for an arbitrary 20-byte MPKH" do
      mpkh = :binary.copy(<<0xAB>>, 20)
      bin = Templates.p2mpkh_locking_script(mpkh)
      assert byte_size(bin) == 70
      assert Templates.p2mpkh_locking_script_len() == 70
    end

    test "matches the spec hex with MPKH spliced into bytes 3..22" do
      mpkh = :binary.copy(<<0xAB>>, 20)
      bin = Templates.p2mpkh_locking_script(mpkh)
      mpkh_hex = String.duplicate("ab", 20)

      # Per spec v0.1 §10.2:
      # 76 a9 14 <MPKH:20> 88 82 01 21 87 63 ac 67
      #   51 7f
      #   (51 7f 73 63 7c 7f 68) x 5
      #   ae 68
      expected_hex =
        "76a914" <>
          mpkh_hex <>
          "888201218763ac67517f" <>
          String.duplicate("517f73637c7f68", 5) <>
          "ae68"

      assert Base.encode16(bin, case: :lower) == expected_hex
    end

    test "MPKH bytes appear at offset 3..22" do
      mpkh = :crypto.strong_rand_bytes(20)
      bin = Templates.p2mpkh_locking_script(mpkh)
      <<_prefix::binary-size(3), embedded::binary-size(20), _suffix::binary>> = bin
      assert embedded == mpkh
    end

    test "round-trips through P2MPKH.mpkh/1 for a real 3-of-5 redeem buffer" do
      pk = fn b -> <<0x02, :binary.copy(<<b>>, 32)::binary>> end
      pubs = [pk.(0x01), pk.(0x02), pk.(0x03), pk.(0x04), pk.(0x05)]
      {:ok, ms} = P2MPKH.new_multisig(3, pubs)

      mpkh = P2MPKH.mpkh(ms)
      bin = Templates.p2mpkh_locking_script(mpkh)

      <<_::binary-size(3), embedded::binary-size(20), _::binary>> = bin
      assert embedded == mpkh
      assert mpkh == Crypto.hash160(P2MPKH.to_script_bytes(ms))
    end

    test "raises on wrong-sized MPKH" do
      assert_raise FunctionClauseError, fn ->
        Templates.p2mpkh_locking_script(<<0::152>>)
      end
    end
  end

  describe "empty_hash160/0" do
    test "equals HASH160(\"\") (= b472a266…3b9fcb)" do
      assert Templates.empty_hash160() == Crypto.hash160("")

      assert Base.encode16(Templates.empty_hash160(), case: :lower) ==
               "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
    end
  end

  # ── STAS 3.0 v0.1 §10.2 single-sig MPKH spend path ────────────────────
  #
  # Spec quote: "Single-sig spend path is taken when the supplied 'pubkey' is
  # exactly 33 bytes (size 0x21), making individual spends from an MPKH
  # address indistinguishable on-chain from a normal P2PKH spend."
  #
  # When MPKH = HASH160(pubkey) for a specific 33-byte pubkey, the 70-byte
  # locking script's `OP_SIZE 0x21 OP_EQUAL OP_IF OP_CHECKSIG` branch fires
  # and the spend looks like a regular P2PKH spend on the wire.
  describe "single-sig MPKH spend path (§10.2)" do
    alias BSV.{PrivateKey, PublicKey}
    alias BSV.Transaction.P2PKH
    alias BSV.Tokens.Script.Templates, as: Tmpls

    test "MPKH = HASH160(pubkey) yields a 70-byte locking script" do
      key = PrivateKey.generate()
      pubkey_bytes = key |> PrivateKey.to_public_key() |> PublicKey.compress() |> Map.get(:point)
      assert byte_size(pubkey_bytes) == 33

      mpkh = Crypto.hash160(pubkey_bytes)
      bin = Tmpls.p2mpkh_locking_script(mpkh)

      assert byte_size(bin) == 70
      <<_::binary-size(3), embedded::binary-size(20), _::binary>> = bin
      assert embedded == mpkh
    end

    test "leading 23 bytes of MPKH body match the canonical P2PKH gate" do
      # The MPKH 70-byte body and a plain 25-byte P2PKH share a common
      # 23-byte prefix `OP_DUP OP_HASH160 OP_DATA_20 <PKH:20>` when MPKH
      # equals HASH160(pubkey). On-chain a wallet observing only the gate
      # cannot distinguish the two leading-region byte runs.
      key = PrivateKey.generate()
      pubkey_bytes = key |> PrivateKey.to_public_key() |> PublicKey.compress() |> Map.get(:point)
      pkh = Crypto.hash160(pubkey_bytes)

      p2pkh_bin = <<0x76, 0xA9, 0x14, pkh::binary, 0x88, 0xAC>>
      mpkh_bin = Tmpls.p2mpkh_locking_script(pkh)

      assert binary_part(p2pkh_bin, 0, 23) == binary_part(mpkh_bin, 0, 23)
    end

    test "P2PKH unlocker (<sig> <33B pubkey>) signs against an MPKH-locked UTXO" do
      # Build a transaction whose source_output uses the canonical 70-byte
      # MPKH locking script for `pkh = HASH160(pubkey)`, sign it with a
      # plain P2PKH unlocker, and verify the result is `<sig> <33B pubkey>` —
      # bit-for-bit indistinguishable from a normal P2PKH spend.
      key = PrivateKey.generate()
      pubkey_bytes = key |> PrivateKey.to_public_key() |> PublicKey.compress() |> Map.get(:point)
      pkh = Crypto.hash160(pubkey_bytes)

      mpkh_bin = Tmpls.p2mpkh_locking_script(pkh)
      {:ok, mpkh_script} = BSV.Script.from_binary(mpkh_bin)

      input = %BSV.Transaction.Input{
        source_txid: :crypto.strong_rand_bytes(32),
        source_tx_out_index: 0,
        source_output: %BSV.Transaction.Output{
          satoshis: 5000,
          locking_script: mpkh_script
        },
        unlocking_script: BSV.Script.new()
      }

      tx = %BSV.Transaction{inputs: [input], outputs: [], version: 1, lock_time: 0}

      unlocker = P2PKH.unlock(key)
      assert {:ok, %BSV.Script{chunks: chunks}} = P2PKH.sign(unlocker, tx, 0)

      assert [{:data, sig}, {:data, embedded_pubkey}] = chunks
      assert byte_size(embedded_pubkey) == 33
      assert embedded_pubkey == pubkey_bytes
      assert byte_size(sig) >= 70
      assert :binary.last(sig) == 0x41
    end
  end
end
