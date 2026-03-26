# PRD: P2MPKH Integration Test Gaps

**Date:** 2026-03-26
**Author:** HAL9000 (code review)
**Builder:** GLaDOS
**Status:** Ready for implementation
**Priority:** High — the multi-key codepath is currently dead code from a testing perspective

---

## 1. Context

Commit `e8738c9` added P2MPKH (Pay-to-Multiple-Public-Key-Hash) support across the SDK. The core P2MPKH module has excellent test coverage (22 tests covering creation, serialization, hashing, and all error branches). However, the **integration layer** — templates, factories, and type resolution that wire P2MPKH into the existing STAS/DSTAS pipeline — has zero test coverage for the multi-key codepath.

All 875 existing tests exercise only the P2PKH (single-key) path. The P2MPKH path through templates and factories is untested.

## 2. Gaps to Fill

### Gap 1: `Payment.resolve_signing_key/1` — 3 branches, 0 tested

**File:** `lib/bsv/tokens/types.ex` (Payment module)

Three branches need testing:
1. `signing_key` present → returns it directly
2. `signing_key` nil, `private_key` present → wraps as `{:single, key}`
3. Both nil → raises

**Test file:** `test/bsv/tokens/payment_resolve_test.exs`

```elixir
# Tests needed:
- resolve_signing_key with explicit signing_key returns it
- resolve_signing_key with only private_key wraps as {:single, key}
- resolve_signing_key with neither raises
```

### Gap 2: `TokenInput.resolve_signing_key/1` — same pattern, 0 tested

**File:** `lib/bsv/tokens/types.ex` (TokenInput module)

Same 3-branch pattern as Payment. Needs identical coverage.

**Test file:** `test/bsv/tokens/token_input_resolve_test.exs` (or add to an existing tokens types test)

### Gap 3: `Template.Stas` P2MPKH signing — the critical path

**File:** `lib/bsv/tokens/template/stas.ex`

The `do_sign({:multi, keys, multisig}, hash, flag)` private function is the heart of P2MPKH support. It produces `<sig1>…<sigM> <multisig_script>` unlocking scripts. Never tested.

**What to test:**

1. **`unlock_mpkh/3` constructor**: Creates a `%Stas{}` with `signing_key: {:multi, ...}`. Verify the struct fields.

2. **`unlock_from_signing_key/2` with multi key**: Same as above but via the dispatch entry point.

3. **`sign/3` with multi key**: This requires building a minimal transaction with a `source_output`. The test should:
   - Generate 3 keys, create a 2-of-3 multisig
   - Build a mock transaction input with a source output (any locking script + satoshis)
   - Call `StasTemplate.sign(template, tx, 0)`
   - Verify the result is `{:ok, %Script{chunks: [sig1_data, sig2_data, ms_data]}}`
   - Verify the last chunk is `{:data, ms_bytes}` where `ms_bytes == P2MPKH.to_script_bytes(multisig)`
   - Verify there are exactly M signature chunks before the multisig script
   - Verify each signature chunk is a DER-encoded signature + sighash flag byte

4. **`estimate_length/3` for multi**: Verify the formula `m * 73 + (3 + n * 34 + 3)` produces correct values for 2-of-3, 1-of-1, 3-of-5.

**Test file:** `test/bsv/tokens/template/stas_p2mpkh_test.exs`

### Gap 4: `Template.Dstas` P2MPKH signing — mirror of Gap 3

**File:** `lib/bsv/tokens/template/dstas.ex`

Identical `do_sign` pattern. Needs at minimum:

1. **`unlock_mpkh/4` constructor** (note: takes `spend_type` as 3rd arg)
2. **`sign/3` with multi key** — same mock transaction approach
3. **`estimate_length/3` for multi path**

**Test file:** `test/bsv/tokens/template/dstas_p2mpkh_test.exs`

### Gap 5: Factory integration with P2MPKH signing key

**File:** `lib/bsv/tokens/factory/stas.ex`

The factories now call `Payment.resolve_signing_key` → `StasTemplate.unlock_from_signing_key`. Test at least one factory operation end-to-end with a multi signing key to verify the wiring works.

**Recommended approach:** Pick `transfer` (simplest factory op with one token input + one funding input). Create a Payment and TokenInput both with `signing_key: {:multi, ...}`. Call the factory and verify `{:ok, tx}` is returned with the expected number of inputs/outputs.

Don't try to verify the transaction is valid on-chain — just verify:
- The factory doesn't crash with multi keys
- The resulting tx has unlocking scripts set on all inputs
- The change output address derives from the MPKH (not a PKH)

**Test file:** `test/bsv/tokens/factory/stas_p2mpkh_test.exs`

### Gap 6: `P2MPKH.sign/3` (standalone bare multisig Template behaviour)

**File:** `lib/bsv/transaction/p2mpkh.ex`

The `sign/3` callback (OP_0 + signatures) is never tested. Needs a mock transaction test similar to Gap 3 but for standalone bare multisig (not STAS).

**Test file:** Add to `test/bsv/transaction/p2mpkh_test.exs`

## 3. Implementation Notes

### Building mock transactions for sign tests

The templates need `tx.inputs[index].source_output` with a `locking_script` and `satoshis`. A minimal helper:

```elixir
defp mock_tx_with_source(locking_script, satoshis) do
  source_output = %BSV.Transaction.Output{
    satoshis: satoshis,
    locking_script: locking_script
  }

  input = %BSV.Transaction.Input{
    prev_txid: :crypto.strong_rand_bytes(32),
    prev_vout: 0,
    source_output: source_output,
    unlocking_script: %BSV.Script{chunks: []}
  }

  %BSV.Transaction{inputs: [input], outputs: [], version: 1, lock_time: 0}
end
```

For STAS template tests, use a simple P2PKH locking script (or the STAS template itself if available). The sighash computation just needs the locking script bytes and satoshis.

### Signature verification

DER-encoded ECDSA signatures are variable length (70-72 bytes typically) plus the 1-byte sighash flag. Verify:
- Each sig chunk is `{:data, sig_bytes}` where `byte_size(sig_bytes)` is in 71..73 range
- Last byte of each sig equals the sighash flag (0x41)

### Change address derivation

For the factory test (Gap 5), verify the change output's locking script contains the MPKH (not a PKH). Extract the 20-byte hash from the P2PKH-style locking script and compare against `P2MPKH.mpkh(multisig)`.

## 4. Acceptance Criteria

- [ ] All 3 branches of `Payment.resolve_signing_key` tested
- [ ] All 3 branches of `TokenInput.resolve_signing_key` tested
- [ ] `Template.Stas.sign/3` tested with multi key — verifies script structure
- [ ] `Template.Dstas.sign/3` tested with multi key — verifies script structure
- [ ] At least one STAS factory op tested end-to-end with multi signing key
- [ ] `P2MPKH.sign/3` (standalone) tested with mock transaction
- [ ] `estimate_length` for multi path tested for multiple m-of-n combos
- [ ] All existing 875 tests still pass (no regressions)
- [ ] New tests are not tautological — they verify structure, not just "no crash"

## 5. Non-Goals

- On-chain transaction verification (no testnet/mainnet)
- Testing the STAS on-chain script's HASH160 verification of the multisig script (that's the node's job)
- New feature development — this is test gap remediation only
