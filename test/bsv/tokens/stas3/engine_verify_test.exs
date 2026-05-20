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
        # Exact fee for the 2899-byte canonical engine template (was 1602
        # under the obsolete 2812-byte template). Recomputed from the
        # error message after the engine swap.
        fee_satoshis: 1646,
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

  # ── swap-swap with §9.5 trailing piece-array ────────────────────────────

  # Build a STAS-3 locking script with a swap action-data descriptor.
  defp stas3_swap_lock(owner_pkh, redemption_pkh, swap) do
    {:ok, scr} =
      Stas3Builder.build_stas3_locking_script(
        owner_pkh,
        redemption_pkh,
        {:swap, swap},
        false,
        false,
        [],
        []
      )

    scr
  end

  # Synthetic 1-in / 1-out preceding tx with `lock` as its sole output's
  # locking script. The HASH256 (sha256d) of these bytes is then used as
  # the corresponding token input's `txid` so the engine's outpoint
  # commitment lines up.
  defp synthetic_preceding_tx(lock, satoshis) do
    lock_bytes = BSV.Script.to_binary(lock)
    len = byte_size(lock_bytes)

    len_field =
      cond do
        len < 0xFD -> <<len>>
        len <= 0xFFFF -> <<0xFD, len::little-16>>
        true -> <<0xFE, len::little-32>>
      end

    <<
      # version
      1::little-32,
      # input count = 1
      1,
      # prev_txid = 32 zero bytes ‖ vout = 0
      0::256,
      0::little-32,
      # scriptSig length = 0
      0,
      # sequence
      0xFFFFFFFF::little-32,
      # output count = 1
      1,
      # value
      satoshis::little-64,
      # script (var-length)
      len_field::binary,
      lock_bytes::binary,
      # locktime
      0::little-32
    >>
  end

  describe "verify/4 — STAS 3.0 swap-swap with §9.5 trailing pieces" do
    @doc """
    Atomic-swap engine verification with the spec v0.2.3 §9.5 trailing
    piece-array auto-wired into both inputs' unlocking scripts. The
    canonical engine (`github.com/stassso/STAS-3-script-templates`)
    consumes pieces via the unrolled `OP_OVER OP_IF OP_SWAP OP_1SUB
    OP_SWAP OP_3 OP_PICK OP_CAT OP_10 OP_ROLL OP_CAT OP_ENDIF` block,
    driven by a decrementing `piece_count` counter.

    **Wiring fix (2026-05-21):** the trailing-piece block is now
    **prepended** to the unlocking script (not appended), so the §7
    no-auth empty push remains on top of stack when the locking script's
    §10.2 P2MPKH redeem-buffer parser runs. With append, the head piece
    was misclassified as a long redeem buffer, OP_SPLIT'd into chunks,
    and the downstream `OP_DUP OP_2 OP_ADD OP_ROLL` overflowed.

    **Remaining failure (2026-05-21):** the Rust mirror now progresses
    past the P2MPKH parser and fails deeper at OP_VERIFY in a HASH256
    chain — the back-to-genesis check (HASH256 of the reconstructed
    preceding_tx vs the input's `prev_txid`) — needs reconstruction
    byte-diff investigation. The encoder/parser correctness is
    validated by the cross-SDK pin test.
    """
    test "swap-swap with pushdata-per-piece trailing is engine-validated" do
      {token_key_a, owner_a_pkh} = generate_keypair()
      {token_key_b, owner_b_pkh} = generate_keypair()
      {fee_key, fee_pkh} = generate_keypair()
      redemption_pkh = :binary.copy(<<0x22>>, 20)

      # Per spec §9.5:
      #   - "Wanted asset is received at the output matching the
      #     initiator's input index" → each input's swap.requested_pkh
      #     MUST equal the matching destination's owner_pkh.
      #   - requested_script_hash MUST be SHA256(counterparty's
      #     locking-script tail) → locks in the counterparty's expected
      #     asset script.
      #
      # Two-pass setup: build with placeholder swap, compute SHA256 of
      # each locking script's tail, then rebuild with the real swaps.
      dest_0_pkh = :binary.copy(<<0x44>>, 20)
      dest_1_pkh = :binary.copy(<<0x55>>, 20)

      placeholder_swap = %{
        requested_script_hash: :binary.copy(<<0x00>>, 32),
        requested_pkh: dest_0_pkh,
        rate_numerator: 1,
        rate_denominator: 1
      }

      placeholder_a = stas3_swap_lock(owner_a_pkh, redemption_pkh, placeholder_swap)
      placeholder_b = stas3_swap_lock(owner_b_pkh, redemption_pkh, placeholder_swap)

      counterparty_hash_for_a =
        BSV.Tokens.Script.Stas3Builder.compute_stas3_requested_script_hash(
          BSV.Script.to_binary(placeholder_b)
        )

      counterparty_hash_for_b =
        BSV.Tokens.Script.Stas3Builder.compute_stas3_requested_script_hash(
          BSV.Script.to_binary(placeholder_a)
        )

      swap_a = %{
        requested_script_hash: counterparty_hash_for_a,
        requested_pkh: dest_0_pkh,
        rate_numerator: 1,
        rate_denominator: 1
      }

      swap_b = %{
        requested_script_hash: counterparty_hash_for_b,
        requested_pkh: dest_1_pkh,
        rate_numerator: 1,
        rate_denominator: 1
      }

      lock_a = stas3_swap_lock(owner_a_pkh, redemption_pkh, swap_a)
      lock_b = stas3_swap_lock(owner_b_pkh, redemption_pkh, swap_b)
      fee_lock = p2pkh_lock(fee_pkh)

      # Build synthetic preceding txs whose HASH256 we then use as the
      # token-input txids. asset_output_index = 0 in both.
      preceding_a = synthetic_preceding_tx(lock_a, 5_000)
      preceding_b = synthetic_preceding_tx(lock_b, 5_000)
      txid_a = BSV.Crypto.sha256d(preceding_a)
      txid_b = BSV.Crypto.sha256d(preceding_b)

      config = %{
        token_inputs: [
          %TokenInput{
            txid: txid_a,
            vout: 0,
            satoshis: 5_000,
            locking_script: lock_a,
            private_key: token_key_a
          },
          %TokenInput{
            txid: txid_b,
            vout: 0,
            satoshis: 5_000,
            locking_script: lock_b,
            private_key: token_key_b
          }
        ],
        fee_txid: :binary.copy(<<0xAA>>, 32),
        fee_vout: 2,
        fee_satoshis: 50_000,
        fee_locking_script: fee_lock,
        fee_private_key: fee_key,
        destinations: [
          %BSV.Tokens.Stas3OutputParams{
            satoshis: 5_000,
            owner_pkh: :binary.copy(<<0x44>>, 20),
            redemption_pkh: redemption_pkh
          },
          %BSV.Tokens.Stas3OutputParams{
            satoshis: 5_000,
            owner_pkh: :binary.copy(<<0x55>>, 20),
            redemption_pkh: redemption_pkh
          }
        ],
        spend_type: :transfer,
        fee_rate: 500
      }

      pieces = [
        %{preceding_tx: preceding_a, asset_output_index: 0},
        %{preceding_tx: preceding_b, asset_output_index: 0}
      ]

      {:ok, tx} = Stas3.build_stas3_swap_swap_tx_with_pieces(config, pieces)

      # Engine acceptance: with the DXS-aligned witness layout (DXS's
      # `prepareMergeInfo` shape spliced in place of slot-18 txType),
      # the canonical engine should accept both inputs.
      assert :ok = EngineVerify.verify(tx, 0, lock_a, 5_000)
      assert :ok = EngineVerify.verify(tx, 1, lock_b, 5_000)
    end
  end
end
