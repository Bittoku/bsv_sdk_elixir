defmodule BSV.Tokens.Stas3UnlockWitnessTest do
  @moduledoc """
  Snapshot tests for STAS 3.0 v0.1 §7 unlocking-script witness assembly.

  Each test pins the exact byte sequence the witness produces — any drift
  from the spec slot ordering or from the "skip vs OP_FALSE" absence rules
  will surface here as a hex-comparison failure.
  """
  use ExUnit.Case, async: true

  alias BSV.Tokens.Stas3UnlockWitness
  alias BSV.Tokens.Script.Stas3Builder

  # ── helpers ────────────────────────────────────────────────────────────

  defp pkh(byte), do: :binary.copy(<<byte>>, 20)
  defp txid(byte), do: :binary.copy(<<byte>>, 32)

  # ── Snapshot 1: 1 STAS output, no change, no note ─────────────────────

  test "encodes a 1-input regular spend with one STAS output, no change, no note" do
    out_pkh = pkh(0xAA)
    var2 = <<>>
    preimage = "preimage-bytes" |> :binary.copy(1)

    w = %Stas3UnlockWitness{
      stas_outputs: [%{amount: 1000, owner_pkh: out_pkh, var2: var2}],
      change: nil,
      note_data: nil,
      funding_input: nil,
      tx_type: :regular,
      sighash_preimage: preimage,
      spend_type: :transfer
    }

    assert {:ok, bytes} = Stas3UnlockWitness.to_script_bytes(w)

    # slot 1: out1_amount (1000 = 0x03E8 → minimal LE: <<0xE8, 0x03>>)
    # slot 2: out1_addr (20-byte push)
    # slot 3: out1_var2 (empty push, treated as OP_0)
    # slots 4-12 SKIPPED (no out2/out3/out4)
    # slot 13: change_amount → OP_FALSE
    # slot 14: change_addr → OP_FALSE
    # slot 15: noteData → OP_FALSE
    # slot 16: fundIdx → OP_FALSE
    # slot 17: fundTxid → OP_FALSE
    # slot 18: txType (1 byte push)
    # slot 19: sighashPreimage push
    # slot 20: spendType (1 byte push)
    expected =
      Stas3Builder.encode_unlock_amount(1000) <>
        Stas3Builder.push_data(out_pkh) <>
        Stas3Builder.push_data(<<>>) <>
        <<0x00>> <>
        <<0x00>> <>
        <<0x00>> <>
        <<0x00>> <>
        <<0x00>> <>
        Stas3Builder.push_data(<<0x00>>) <>
        Stas3Builder.push_data(preimage) <>
        Stas3Builder.push_data(<<0x01>>)

    assert bytes == expected
  end

  # ── Snapshot 2: 1 STAS output WITH change, no note ────────────────────

  test "encodes a 1 STAS output spend with change" do
    out_pkh = pkh(0xAA)
    change_pkh = pkh(0xCC)
    var2 = <<>>
    preimage = <<0x99, 0x88, 0x77>>

    w = %Stas3UnlockWitness{
      stas_outputs: [%{amount: 950, owner_pkh: out_pkh, var2: var2}],
      change: %{amount: 1234, addr_pkh: change_pkh},
      note_data: nil,
      funding_input: nil,
      tx_type: :regular,
      sighash_preimage: preimage,
      spend_type: :transfer
    }

    assert {:ok, bytes} = Stas3UnlockWitness.to_script_bytes(w)

    expected =
      Stas3Builder.encode_unlock_amount(950) <>
        Stas3Builder.push_data(out_pkh) <>
        Stas3Builder.push_data(<<>>) <>
        Stas3Builder.encode_unlock_amount(1234) <>
        Stas3Builder.push_data(change_pkh) <>
        <<0x00>> <>
        <<0x00>> <>
        <<0x00>> <>
        Stas3Builder.push_data(<<0x00>>) <>
        Stas3Builder.push_data(preimage) <>
        Stas3Builder.push_data(<<0x01>>)

    assert bytes == expected
  end

  # ── Snapshot 3: 2-output split (one STAS + change) ────────────────────

  test "encodes a 2 STAS output split with change and a small note" do
    out1_pkh = pkh(0x11)
    out2_pkh = pkh(0x22)
    change_pkh = pkh(0x33)
    note = <<0xDE, 0xAD, 0xBE, 0xEF>>
    preimage = <<0x42>>

    fund_txid = txid(0x55)
    fund_vout = 7

    w = %Stas3UnlockWitness{
      stas_outputs: [
        %{amount: 600, owner_pkh: out1_pkh, var2: <<>>},
        %{amount: 400, owner_pkh: out2_pkh, var2: <<>>}
      ],
      change: %{amount: 100, addr_pkh: change_pkh},
      note_data: note,
      funding_input: %{txid: fund_txid, vout: fund_vout},
      tx_type: :regular,
      sighash_preimage: preimage,
      spend_type: :transfer
    }

    assert {:ok, bytes} = Stas3UnlockWitness.to_script_bytes(w)

    # slots 7-12 SKIPPED
    expected =
      Stas3Builder.encode_unlock_amount(600) <>
        Stas3Builder.push_data(out1_pkh) <>
        Stas3Builder.push_data(<<>>) <>
        Stas3Builder.encode_unlock_amount(400) <>
        Stas3Builder.push_data(out2_pkh) <>
        Stas3Builder.push_data(<<>>) <>
        Stas3Builder.encode_unlock_amount(100) <>
        Stas3Builder.push_data(change_pkh) <>
        Stas3Builder.push_data(note) <>
        Stas3Builder.push_data(<<fund_vout::little-32>>) <>
        Stas3Builder.push_data(fund_txid) <>
        Stas3Builder.push_data(<<0x00>>) <>
        Stas3Builder.push_data(preimage) <>
        Stas3Builder.push_data(<<0x01>>)

    assert bytes == expected
  end

  # ── Snapshot 4: confiscation (txType=5, spendType=3) ───────────────────

  test "encodes a confiscation with tx_type=5 (merge_5) and spend_type=3" do
    out1_pkh = pkh(0xEE)
    preimage = <<0x12, 0x34>>

    w = %Stas3UnlockWitness{
      stas_outputs: [%{amount: 4242, owner_pkh: out1_pkh, var2: <<>>}],
      change: nil,
      note_data: nil,
      funding_input: nil,
      tx_type: :merge_5,
      sighash_preimage: preimage,
      spend_type: :confiscation
    }

    assert {:ok, bytes} = Stas3UnlockWitness.to_script_bytes(w)

    expected =
      Stas3Builder.encode_unlock_amount(4242) <>
        Stas3Builder.push_data(out1_pkh) <>
        Stas3Builder.push_data(<<>>) <>
        <<0x00>> <>
        <<0x00>> <>
        <<0x00>> <>
        <<0x00>> <>
        <<0x00>> <>
        Stas3Builder.push_data(<<0x05>>) <>
        Stas3Builder.push_data(preimage) <>
        Stas3Builder.push_data(<<0x03>>)

    assert bytes == expected
  end

  # ── Validation paths ───────────────────────────────────────────────────

  test "rejects note_data exceeding 65 533 B" do
    too_big = :binary.copy(<<0x00>>, 65_534)

    w = %Stas3UnlockWitness{
      stas_outputs: [%{amount: 1, owner_pkh: pkh(0x01), var2: <<>>}],
      note_data: too_big,
      tx_type: :regular,
      sighash_preimage: <<0x01>>,
      spend_type: :transfer
    }

    assert {:error, :note_data_too_large} = Stas3UnlockWitness.to_script_bytes(w)
  end

  test "rejects more than 4 STAS outputs" do
    outs =
      for i <- 1..5,
          do: %{amount: i, owner_pkh: pkh(i), var2: <<>>}

    w = %Stas3UnlockWitness{
      stas_outputs: outs,
      tx_type: :regular,
      sighash_preimage: <<>>,
      spend_type: :transfer
    }

    assert {:error, {:too_many_stas_outputs, 5}} = Stas3UnlockWitness.to_script_bytes(w)
  end

  test "max_note_bytes exposes spec MAX_NOTE_BYTES (65 533)" do
    assert Stas3UnlockWitness.max_note_bytes() == 65_533
  end

  # ── BSV.Tokens.Template.Stas3 wiring: unlock script = witness ‖ authz ──

  describe "Template.Stas3 wiring" do
    alias BSV.{PrivateKey, Script}
    alias BSV.Transaction
    alias BSV.Transaction.{Input, Output}
    alias BSV.Tokens.Template.Stas3, as: Stas3Template

    defp p2pkh_locking_script do
      key = PrivateKey.generate()
      pubkey = PrivateKey.to_public_key(key) |> BSV.PublicKey.compress()
      pkh = BSV.Crypto.hash160(pubkey.point)
      addr = BSV.Base58.check_encode(pkh, 0x00)
      {:ok, script} = BSV.Script.Address.to_script(addr)
      script
    end

    defp tx_with_source(satoshis) do
      input = %Input{
        source_txid: :crypto.strong_rand_bytes(32),
        source_tx_out_index: 0,
        source_output: %Output{satoshis: satoshis, locking_script: p2pkh_locking_script()},
        unlocking_script: Script.new()
      }

      %Transaction{inputs: [input], outputs: [], version: 1, lock_time: 0}
    end

    test "with_witness/2 prepends witness bytes to authz script" do
      key = PrivateKey.generate()
      tpl = Stas3Template.unlock(key, :transfer)

      witness = %Stas3UnlockWitness{
        stas_outputs: [%{amount: 1, owner_pkh: pkh(0xAA), var2: <<>>}],
        tx_type: :regular,
        sighash_preimage: <<0xAB, 0xCD>>,
        spend_type: :transfer
      }

      tpl = Stas3Template.with_witness(tpl, witness)
      tx = tx_with_source(1000)

      assert {:ok, %Script{} = combined} = Stas3Template.sign(tpl, tx, 0)
      combined_bin = Script.to_binary(combined)

      {:ok, witness_bytes} = Stas3UnlockWitness.to_script_bytes(witness)
      assert binary_part(combined_bin, 0, byte_size(witness_bytes)) == witness_bytes
      assert byte_size(combined_bin) > byte_size(witness_bytes)
    end

    test "no_auth template with witness produces witness ‖ OP_FALSE (real slot-19 preimage preserved)" do
      tpl = Stas3Template.unlock_no_auth(:transfer)

      # Per the spec author's §10.3 clarification, the "preimage" replaced
      # with OP_FALSE is the address/MPKH preimage (authz slot 21+), NOT
      # the slot-19 sighashPreimage. Use a non-trivial preimage value so a
      # silent "drop slot 19" regression would surface here as a length /
      # bytes mismatch.
      real_preimage = :binary.copy(<<0xAB>>, 200)

      witness = %Stas3UnlockWitness{
        stas_outputs: [%{amount: 1, owner_pkh: pkh(0xAA), var2: <<>>}],
        tx_type: :regular,
        sighash_preimage: real_preimage,
        spend_type: :transfer
      }

      tpl = Stas3Template.with_witness(tpl, witness)
      tx = tx_with_source(500)

      assert {:ok, %Script{} = combined} = Stas3Template.sign(tpl, tx, 0)
      combined_bin = Script.to_binary(combined)
      {:ok, witness_bytes} = Stas3UnlockWitness.to_script_bytes(witness)

      # Authz region = single OP_FALSE push.
      assert combined_bin == witness_bytes <> <<0x00>>

      # Slot 19 inside the witness MUST contain the real preimage bytes
      # verbatim — re-decode and inspect the chunk layout.
      {:ok, %Script{chunks: chunks}} = Script.from_binary(combined_bin)
      [authz_chunk, spend_type_chunk, preimage_chunk | _] = Enum.reverse(chunks)
      assert authz_chunk == {:data, <<>>}
      assert spend_type_chunk == {:data, <<0x01>>}
      assert preimage_chunk == {:data, real_preimage}
    end

    test "without witness, sign/3 emits authz only (legacy behaviour preserved)" do
      key = PrivateKey.generate()
      tpl = Stas3Template.unlock(key, :transfer)
      tx = tx_with_source(1000)

      assert {:ok, %Script{chunks: chunks}} = Stas3Template.sign(tpl, tx, 0)
      # P2PKH unlock = <sig> <pubkey>
      assert length(chunks) == 2
    end
  end
end
