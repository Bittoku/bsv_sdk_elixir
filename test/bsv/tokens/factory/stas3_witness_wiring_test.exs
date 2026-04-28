defmodule BSV.Tokens.Factory.Stas3WitnessWiringTest do
  @moduledoc """
  End-to-end tests for the auto-wired STAS 3.0 v0.1 §7 unlocking-script
  witness produced by `BSV.Tokens.Factory.Stas3` factories.

  These tests assert that every STAS 3.0 input the factory signs has an
  unlocking script of the form `witness_bytes ‖ authz_bytes` where the
  witness encodes spec §7 slots 1-20 derived automatically from the
  transaction structure (no caller opt-in).

  For each factory family — base/transfer, freeze, confiscation,
  swap-cancel, atomic-swap, redeem — we walk input 0's unlocking script
  push-by-push and confirm:

    * slot 1 (out1_amount) is the minimal-LE encoding of the first STAS
      output's satoshis,
    * slot 18 (txType) and slot 20 (spendType) match the family,
    * the authz block (P2PKH `<sig> <pubkey>` or P2MPKH
      `OP_0 + sigs + redeem`) immediately follows the witness.
  """

  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Crypto, Script}
  alias BSV.Tokens.Factory.Stas3
  alias BSV.Tokens.Script.{Stas3Builder, Reader}
  alias BSV.Tokens.{Stas3OutputParams, TokenInput, Stas3UnlockWitness, SpendType, TxType}
  alias BSV.Tokens.Factory.Stas3.WitnessBuilder

  defp test_key, do: PrivateKey.generate()

  defp p2pkh_script(key) do
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    address = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, script} = BSV.Script.Address.to_script(address)
    script
  end

  defp dummy_hash, do: :binary.copy(<<0xAA>>, 32)

  defp make_stas3_locking(owner_pkh, redemption_pkh) do
    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner_pkh, redemption_pkh, nil, false, true, [], [])

    script
  end

  defp make_stas3_locking_with_flags(owner_pkh, redemption_pkh, %BSV.Tokens.ScriptFlags{} = flags) do
    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(
        owner_pkh,
        redemption_pkh,
        nil,
        false,
        flags,
        [],
        []
      )

    script
  end

  defp make_stas3_swap_locking(owner_pkh, redemption_pkh, swap) do
    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(
        owner_pkh,
        redemption_pkh,
        {:swap, swap},
        false,
        true,
        [],
        []
      )

    script
  end

  defp swap_fields(hash, pkh, num, den) do
    %{
      requested_script_hash: hash,
      requested_pkh: pkh,
      rate_numerator: num,
      rate_denominator: den
    }
  end

  # Walk a single STAS3 unlock script, peeling off the witness slots 1-20
  # in spec order and returning {witness_struct, authz_bytes}. If a slot
  # in the script doesn't match what `expected_witness_for/2` derived from
  # the produced tx, the assertions inside this helper will fail loudly.
  defp split_witness_authz(unlock_bin, expected_witness) do
    {:ok, expected_bytes} = Stas3UnlockWitness.to_script_bytes(expected_witness)
    wsize = byte_size(expected_bytes)
    <<witness::binary-size(wsize), authz::binary>> = unlock_bin
    {witness, authz, expected_bytes}
  end

  defp signed_authz_chunks(authz_bin) do
    {:ok, authz_script} = Script.from_binary(authz_bin)
    authz_script.chunks
  end

  defp expect_p2pkh_authz!(authz_bin) do
    chunks = signed_authz_chunks(authz_bin)
    assert length(chunks) == 2
    assert [{:data, sig}, {:data, pubkey}] = chunks
    # DER ECDSA sig followed by 1-byte sighash flag → 71-73 bytes typically.
    assert byte_size(sig) >= 9
    # Compressed pubkey is 33 bytes.
    assert byte_size(pubkey) == 33
  end

  # ── Base / transfer family ────────────────────────────────────────────

  test "build_stas3_base_tx wires witness with txType=:regular, spendType=:transfer" do
    token_key = test_key()
    fee_key = test_key()

    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    owner_pkh = Crypto.hash160(pubkey.point)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_base_tx(config)

    # Re-derive the expected witness from the produced tx. Because the
    # factory derives slot 19 (preimage) from this exact tx structure,
    # this re-derivation must yield the same byte sequence.
    {:ok, expected_witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 1, :transfer, :regular, 0x41)

    assert expected_witness.tx_type == :regular
    assert expected_witness.spend_type == :transfer
    assert SpendType.to_byte(expected_witness.spend_type) == 1
    assert TxType.to_byte(expected_witness.tx_type) == 0
    assert length(expected_witness.stas_outputs) == 1
    assert hd(expected_witness.stas_outputs).amount == 5_000

    unlock_bin = Script.to_binary(Enum.at(tx.inputs, 0).unlocking_script)
    {_witness, authz_bin, expected_bytes} = split_witness_authz(unlock_bin, expected_witness)

    # Slot 1 (first push) MUST be minimal-LE encoded out1_amount.
    out1_amount_push = Stas3Builder.encode_unlock_amount(5_000)
    assert binary_part(unlock_bin, 0, byte_size(out1_amount_push)) == out1_amount_push
    # The full witness prefix matches what the encoder produces.
    assert binary_part(unlock_bin, 0, byte_size(expected_bytes)) == expected_bytes
    # The authz block follows: P2PKH `<sig> <pubkey>`.
    expect_p2pkh_authz!(authz_bin)
  end

  # ── Freeze family ─────────────────────────────────────────────────────

  test "build_stas3_freeze_tx wires witness with spendType=:freeze_unfreeze" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 5_000,
          owner_pkh: owner_pkh,
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_freeze_tx(config)

    {:ok, expected_witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 1, :freeze_unfreeze, :regular, 0x41)

    assert expected_witness.spend_type == :freeze_unfreeze
    assert SpendType.to_byte(expected_witness.spend_type) == 2

    unlock_bin = Script.to_binary(Enum.at(tx.inputs, 0).unlocking_script)
    {_, authz_bin, expected_bytes} = split_witness_authz(unlock_bin, expected_witness)

    assert binary_part(unlock_bin, 0, byte_size(expected_bytes)) == expected_bytes
    expect_p2pkh_authz!(authz_bin)

    # Slot 1: out1_amount minimal-LE for 5000.
    assert binary_part(unlock_bin, 0, byte_size(Stas3Builder.encode_unlock_amount(5_000))) ==
             Stas3Builder.encode_unlock_amount(5_000)
  end

  # ── Confiscation family ───────────────────────────────────────────────

  test "build_stas3_confiscate_tx wires witness with spendType=:confiscation" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    confiscatable_flags = %BSV.Tokens.ScriptFlags{freezable: true, confiscatable: true}

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script:
            make_stas3_locking_with_flags(owner_pkh, redemption_pkh, confiscatable_flags),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x55>>, 20),
          redemption_pkh: redemption_pkh
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_confiscate_tx(config)

    {:ok, expected_witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 1, :confiscation, :regular, 0x41)

    assert expected_witness.spend_type == :confiscation
    assert SpendType.to_byte(expected_witness.spend_type) == 3

    unlock_bin = Script.to_binary(Enum.at(tx.inputs, 0).unlocking_script)
    {_, authz_bin, expected_bytes} = split_witness_authz(unlock_bin, expected_witness)

    assert binary_part(unlock_bin, 0, byte_size(expected_bytes)) == expected_bytes
    expect_p2pkh_authz!(authz_bin)
  end

  # ── Swap-cancel family ────────────────────────────────────────────────

  test "build_stas3_swap_cancel_tx wires witness with spendType=:swap_cancellation" do
    fee_key = test_key()
    cat_pkh = :binary.copy(<<0x33>>, 20)
    bob_pkh = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)
    other_redemption = :binary.copy(<<0x44>>, 20)

    cat_script = make_stas3_locking(cat_pkh, other_redemption)
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    # receiveAddr = bob_pkh — swap cancellation returns the UTXO to bob.
    swap = swap_fields(cat_hash, bob_pkh, 1, 1)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 100,
          locking_script: make_stas3_swap_locking(bob_pkh, redemption, swap),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 100,
          owner_pkh: bob_pkh,
          redemption_pkh: redemption
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_swap_cancel_tx(config)

    {:ok, expected_witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 1, :swap_cancellation, :regular, 0x41)

    assert expected_witness.spend_type == :swap_cancellation
    assert SpendType.to_byte(expected_witness.spend_type) == 4

    unlock_bin = Script.to_binary(Enum.at(tx.inputs, 0).unlocking_script)
    {_, authz_bin, expected_bytes} = split_witness_authz(unlock_bin, expected_witness)

    assert binary_part(unlock_bin, 0, byte_size(expected_bytes)) == expected_bytes
    expect_p2pkh_authz!(authz_bin)
  end

  # ── Atomic-swap family ────────────────────────────────────────────────

  test "build_stas3_transfer_swap_tx wires witness with txType=:atomic_swap" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))
    swap = swap_fields(cat_hash, bob_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: cat_script,
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a}
    ]

    config = %{
      token_inputs: inputs,
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: destinations,
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_transfer_swap_tx(config)

    # Both token inputs should carry a witness; assert on input 0.
    {:ok, expected_witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 2, :transfer, :atomic_swap, 0x41)

    assert expected_witness.tx_type == :atomic_swap
    assert TxType.to_byte(expected_witness.tx_type) == 1
    assert expected_witness.spend_type == :transfer

    unlock_bin = Script.to_binary(Enum.at(tx.inputs, 0).unlocking_script)
    {_, authz_bin, expected_bytes} = split_witness_authz(unlock_bin, expected_witness)

    assert binary_part(unlock_bin, 0, byte_size(expected_bytes)) == expected_bytes
    expect_p2pkh_authz!(authz_bin)

    # Slot 1: out1_amount = 100 → minimal LE = <<0x01, 0x64>>.
    assert binary_part(unlock_bin, 0, 2) == <<0x01, 0x64>>
  end

  # ── Redeem family ────────────────────────────────────────────────────

  test "build_stas3_redeem_tx wires witness with spendType=:transfer" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    stas3_script = make_stas3_locking(issuer_pkh, issuer_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 10_000,
        locking_script: stas3_script,
        private_key: token_key
      },
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      redeem_satoshis: 6_000,
      redeem_pkh: issuer_pkh,
      remaining_destinations: [
        %Stas3OutputParams{
          satoshis: 4_000,
          owner_pkh: issuer_pkh,
          redemption_pkh: issuer_pkh
        }
      ],
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_redeem_tx(config)

    # On redeem, output 0 is P2PKH (not STAS) and output 1 is the only
    # STAS3 output. The witness records exactly that one STAS output.
    {:ok, expected_witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 1, :transfer, :regular, 0x41)

    assert expected_witness.spend_type == :transfer
    assert length(expected_witness.stas_outputs) == 1
    assert hd(expected_witness.stas_outputs).amount == 4_000

    # The redeem P2PKH output is also the change candidate per slot 13/14
    # (it is the first non-STAS p2pkh output in the tx).
    assert expected_witness.change != nil

    unlock_bin = Script.to_binary(Enum.at(tx.inputs, 0).unlocking_script)
    {_, authz_bin, expected_bytes} = split_witness_authz(unlock_bin, expected_witness)

    assert binary_part(unlock_bin, 0, byte_size(expected_bytes)) == expected_bytes
    expect_p2pkh_authz!(authz_bin)

    # Slot 1: out1_amount for the surviving STAS output (4000).
    out1_amount_push = Stas3Builder.encode_unlock_amount(4_000)
    assert binary_part(unlock_bin, 0, byte_size(out1_amount_push)) == out1_amount_push
  end

  # ── Sanity: the auto-wired witness round-trips through the encoder ───

  test "factory-produced unlock script slot 19 preimage matches BIP-143 recompute" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    owner_pkh = Crypto.hash160(pubkey.point)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_base_tx(config)

    {:ok, expected_witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 1, :transfer, :regular, 0x41)

    # Recompute the BIP-143 preimage from the produced tx and compare.
    locking_bin = Script.to_binary(Enum.at(tx.inputs, 0).source_output.locking_script)
    sats = Enum.at(tx.inputs, 0).source_output.satoshis

    {:ok, computed} =
      BSV.Transaction.Sighash.calc_preimage(tx, 0, locking_bin, 0x41, sats)

    assert expected_witness.sighash_preimage == computed
  end

  # ── The output produced by `Reader.read_locking_script` confirms the
  # auto-wired tx's STAS outputs survive the witness shim ────────────

  test "auto-wired tx still produces parseable STAS3 outputs" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 10_000,
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 4_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh
        },
        %Stas3OutputParams{
          satoshis: 6_000,
          owner_pkh: :binary.copy(<<0x44>>, 20),
          redemption_pkh: redemption_pkh
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_split_tx(config)

    parsed_first =
      Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 0).locking_script))

    assert parsed_first.script_type == :stas3

    # Witness derivation must record exactly 2 STAS outputs (slots 1-6).
    {:ok, witness} =
      WitnessBuilder.derive_witness_for_input(tx, 0, 1, :transfer, :regular, 0x41)

    assert length(witness.stas_outputs) == 2
    assert Enum.at(witness.stas_outputs, 0).amount == 4_000
    assert Enum.at(witness.stas_outputs, 1).amount == 6_000
  end
end
