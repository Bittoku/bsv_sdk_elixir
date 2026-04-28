defmodule BSV.Tokens.Stas3.EngineVerifyTest do
  @moduledoc """
  End-to-end engine verification for STAS 3.0 transactions produced by the
  `BSV.Tokens.Factory.Stas3` factory.

  These tests build a real spend tx, then run the SDK's full script
  interpreter against the (unlock_script, locking_script) pair using a
  BIP-143 + ECDSA sighash function. A pass means the engine accepted the
  pair byte-for-byte; a failure surfaces the exact interpreter error
  (e.g. `:invalid_split_range`).
  """
  use ExUnit.Case, async: true

  import Bitwise
  alias BSV.{Crypto, PrivateKey, PublicKey}
  alias BSV.Tokens.Factory.Stas3
  alias BSV.Tokens.{TokenInput, Stas3OutputParams}
  alias BSV.Tokens.Script.Stas3Builder
  alias BSV.Tokens.Stas3.EngineVerify

  # ── helpers ──────────────────────────────────────────────────────────────

  defp p2pkh_lock(pkh) do
    addr = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, scr} = BSV.Script.Address.to_script(addr)
    scr
  end

  # Build a STAS 3.0 locking script with a fixed redemption PKH and the
  # given owner. `freezable` is required and matters for the engine's
  # service-field lookup; passing `true` without a service field would
  # leave the engine reaching for absent data and trip `:invalid_split_range`.
  defp stas3_lock(owner_pkh, redemption_pkh, freezable) do
    {:ok, scr} =
      Stas3Builder.build_stas3_locking_script(
        owner_pkh,
        redemption_pkh,
        nil,
        false,
        freezable,
        [],
        []
      )

    scr
  end

  defp generate_keypair do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    {key, pkh}
  end

  defp default_dest(owner_pkh, redemption_pkh, satoshis, opts \\ []) do
    %Stas3OutputParams{
      satoshis: satoshis,
      owner_pkh: owner_pkh,
      redemption_pkh: redemption_pkh,
      freezable: Keyword.get(opts, :freezable, false),
      frozen: Keyword.get(opts, :frozen, false),
      action_data: Keyword.get(opts, :action_data, nil)
    }
  end

  # ── 1-in / 1-out transfer ────────────────────────────────────────────────

  describe "verify/4 — STAS 3.0 transfer" do
    test "1-input/1-output transfer is accepted by the script interpreter" do
      {token_key, owner_pkh} = generate_keypair()
      {fee_key, fee_pkh} = generate_keypair()
      redemption_pkh = :binary.copy(<<0x22>>, 20)

      lock_script = stas3_lock(owner_pkh, redemption_pkh, false)
      fee_lock = p2pkh_lock(fee_pkh)
      dummy = :crypto.strong_rand_bytes(32)

      config = %{
        token_inputs: [
          %TokenInput{
            txid: dummy,
            vout: 0,
            satoshis: 5_000,
            locking_script: lock_script,
            private_key: token_key
          }
        ],
        fee_txid: dummy,
        fee_vout: 1,
        fee_satoshis: 50_000,
        fee_locking_script: fee_lock,
        fee_private_key: fee_key,
        destinations: [
          default_dest(:binary.copy(<<0x33>>, 20), redemption_pkh, 5_000)
        ],
        spend_type: :transfer,
        fee_rate: 500
      }

      {:ok, tx} = Stas3.build_stas3_base_tx(config)
      assert :ok = EngineVerify.verify(tx, 0, lock_script, 5_000)
    end

    test "1-input/1-output transfer with no change output (exact fee)" do
      {token_key, owner_pkh} = generate_keypair()
      {fee_key, fee_pkh} = generate_keypair()
      redemption_pkh = :binary.copy(<<0x22>>, 20)

      lock_script = stas3_lock(owner_pkh, redemption_pkh, false)
      fee_lock = p2pkh_lock(fee_pkh)
      dummy = :crypto.strong_rand_bytes(32)

      config = %{
        token_inputs: [
          %TokenInput{
            txid: dummy,
            vout: 0,
            satoshis: 5_000,
            locking_script: lock_script,
            private_key: token_key
          }
        ],
        fee_txid: dummy,
        fee_vout: 1,
        fee_satoshis: 1602,
        fee_locking_script: fee_lock,
        fee_private_key: fee_key,
        destinations: [
          default_dest(:binary.copy(<<0x33>>, 20), redemption_pkh, 5_000)
        ],
        spend_type: :transfer,
        fee_rate: 500
      }

      {:ok, tx} = Stas3.build_stas3_base_tx(config)
      assert :ok = EngineVerify.verify(tx, 0, lock_script, 5_000)
    end

    test "1-input/1-output transfer with change amount that would otherwise overflow into the script-num sign bit" do
      # Fee_satoshis chosen so the change amount lands at exactly 0xBD0E
      # (48398) — high bit of MSB set, the failure mode that originally
      # caused :invalid_split_range / :eval_false in the engine. This is
      # the regression guard for the script-num sign-bit fix in
      # `Stas3Builder.encode_unlock_amount/1`.
      {token_key, owner_pkh} = generate_keypair()
      {fee_key, fee_pkh} = generate_keypair()
      redemption_pkh = :binary.copy(<<0x22>>, 20)

      lock_script = stas3_lock(owner_pkh, redemption_pkh, false)
      fee_lock = p2pkh_lock(fee_pkh)
      dummy = :crypto.strong_rand_bytes(32)

      config = %{
        token_inputs: [
          %TokenInput{
            txid: dummy,
            vout: 0,
            satoshis: 5_000,
            locking_script: lock_script,
            private_key: token_key
          }
        ],
        fee_txid: dummy,
        fee_vout: 1,
        fee_satoshis: 50_000,
        fee_locking_script: fee_lock,
        fee_private_key: fee_key,
        destinations: [
          default_dest(:binary.copy(<<0x33>>, 20), redemption_pkh, 5_000)
        ],
        spend_type: :transfer,
        fee_rate: 500
      }

      {:ok, tx} = Stas3.build_stas3_base_tx(config)
      change_amt = Enum.at(tx.outputs, 1).satoshis

      # sanity: this is the high-bit-set regime the original bug hit.
      assert change_amt > 0
      assert <<_lo, hi_byte>> = <<change_amt::little-16>>

      assert band(hi_byte, 0x80) != 0,
             "test setup expects change MSB high-bit set (#{change_amt})"

      assert :ok = EngineVerify.verify(tx, 0, lock_script, 5_000)
    end

    test "split into 2 STAS outputs is accepted" do
      {token_key, owner_pkh} = generate_keypair()
      {fee_key, fee_pkh} = generate_keypair()
      redemption_pkh = :binary.copy(<<0x22>>, 20)

      lock_script = stas3_lock(owner_pkh, redemption_pkh, false)
      fee_lock = p2pkh_lock(fee_pkh)
      dummy = :crypto.strong_rand_bytes(32)

      config = %{
        token_inputs: [
          %TokenInput{
            txid: dummy,
            vout: 0,
            satoshis: 10_000,
            locking_script: lock_script,
            private_key: token_key
          }
        ],
        fee_txid: dummy,
        fee_vout: 1,
        fee_satoshis: 50_000,
        fee_locking_script: fee_lock,
        fee_private_key: fee_key,
        destinations: [
          default_dest(:binary.copy(<<0x33>>, 20), redemption_pkh, 6_000),
          default_dest(:binary.copy(<<0x44>>, 20), redemption_pkh, 4_000)
        ],
        spend_type: :transfer,
        fee_rate: 500
      }

      {:ok, tx} = Stas3.build_stas3_base_tx(config)
      assert :ok = EngineVerify.verify(tx, 0, lock_script, 10_000)
    end
  end
end
