# Changelog

## v1.5.0 — 2026-05-01

### STAS 3.0 v0.1 — spec finalization & engine validation

- **§7 unlock-witness encoder** — `BSV.Tokens.Stas3UnlockWitness` struct
  with slots 1–20 (STAS-output triplets, change/note/funding pointers,
  txType, BIP-143 preimage, spendType). `to_script_bytes/1` emits spec
  push order with absent-slot OP_FALSE handling and 65533-byte noteData
  cap. Wired into the template via `Template.Stas3.with_witness/2`.
- **Auto-wired into every factory** — `build_stas3_base_tx`, `_split_tx`,
  `_merge_tx`, `_freeze_tx`, `_unfreeze_tx`, `_confiscate_tx`,
  `_swap_cancel_tx`, `_redeem_tx`, `_transfer_swap_tx`, `_swap_swap_tx`
  now derive a per-input witness via `WitnessBuilder.derive_witness_for_input/6`
  and attach it through the dispatcher. SDK-built txs are engine-validatable
  by default — no caller opt-in required.
- **§9 build-time enforcement** — `BSV.Tokens.Stas3.Validate` rejects
  multi-output freeze, owner/redemption drift, FREEZABLE flag missing,
  CONFISCATABLE flag missing, multi-output swap_cancel, and
  swap_cancel without a swap descriptor.
- **§9.5 atomic-swap and merge piece arrays** — `BSV.Tokens.Script.Stas3Pieces`
  encodes the trailing parameter block carried after authz in atomic-swap
  (txType=1) and merge (txType=2..7) unlocking scripts. Pieces are
  **length-prefixed** (1-byte length per piece), corrected from the earlier
  space-delimited reading of the spec wording. Pieces > 255 bytes return
  `{:error, :invalid_piece}`.
- **§6.3 recursive swap descriptor** — `BSV.Tokens.SwapDescriptor` carries
  optional `next` for the maker's remainder UTXO. Variants:
  `{:passive, binary}`, `:frozen`, `{:swap, %SwapDescriptor{}}` (recursive,
  leading 0x01 stripped). Three-level recursive snapshot pinned at 181 bytes,
  byte-equal to the Rust SDK reference vector.
- **§10.3 no-auth template** — single OP_FALSE in the address/MPKH preimage
  slot (slot 21+); slot 19 always carries the real BIP-143 preimage. Spec
  author confirmation captured in moduledoc.
- **`BSV.Tokens.TxType`** — typed enum `{regular, atomic_swap, merge_2..merge_7}`
  mirroring `SpendType`.

### P2MPKH spec §10.2 finalization

- Redeem buffer is `[m: 1B raw][0x21 pk]xN[n: 1B raw]` (length 2 + 34N) —
  raw bytes for m/n, no OP_CHECKMULTISIG terminator. MPKH = HASH160(buffer).
- Fixed 70-byte P2MPKH locking script body via
  `Templates.p2mpkh_locking_script/1` for issuance and redemption outputs.
- `p2mpkh?/1` rewritten against the spec body; legacy bare-multisig form
  rejected. `@max_keys` lowered 16 → 5 per spec.
- Cross-SDK reference vector pinned: 3-of-5 i*G with MPKH
  `deb7bfb8b45c2bfe4579af5126b46c4d95e4e3a6` and 172-byte redeem buffer.

### End-to-end engine verification

- New `BSV.Tokens.Stas3.EngineVerify.verify/4` runs an SDK-built STAS 3.0
  transaction through `BSV.Script.Interpreter` with real BIP-143 + ECDSA
  sighash. Engine accepts SDK transactions for transfer (with/without
  change) and 2-output split scenarios.
- **Bug fixed: `encode_unlock_amount/1` script-num sign-bit overflow** —
  amounts whose high byte had bit 7 set (e.g. 48398 → `<<0x0E, 0xBD>>`)
  decoded as negative under script-num rules, breaking BIP-143
  `hashOutputs` reconstruction. New `amount_to_script_num_le/1` appends a
  `<<0x00>>` sentinel when needed. Regression test asserts the MSB-bit-7
  case round-trips through the engine.
- **Bug fixed: Genesis-rules `OP_RETURN` in `BSV.Script.Interpreter`** —
  post-Genesis OP_RETURN is inert; execution continues past it preserving
  final-stack truthiness. Without this every STAS 3.0 lock script failed at
  the 0x6a opcode preceding the metadata tail. Opt-in opcode tracing
  (`:trace`, `:trace_path` opts) added for future debugging.

### Tests

- 1071 tests, 0 failures.

## v1.4.0 — 2026-04-15

- `BSV.Tokens.Script.Reader.read_push_data/1` handles all pushdata
  opcodes (direct push 0x01..0x4b, OP_PUSHDATA1/2/4) per STAS 3.0 spec.
- P2MPKH support in STAS3 issuance, redemption, and script detection.
- New opcode-extraction test coverage for `read_push_data`.

## v1.3.0 — 2026-04-08

- Rename `dSTAS` / `DSTAS` / `Gen3` → **STAS 3** / **STAS 3.0** across
  identifiers, moduledocs, display strings, and docs. STAS3 naming
  finalized per upstream spec.

## v1.2.1

- Hex package now includes `priv/`.

## v1.2.0 — 2026-03-26

### New Features

- **P2MPKH (Pay-to-Multiple-Public-Key-Hash)** — m-of-n multisig ownership for STAS/STAS3 tokens
  - `BSV.Transaction.P2MPKH`: MultisigScript creation, serialization, MPKH (HASH160), lock/unlock
  - `BSV.Tokens.SigningKey`: `{:single, key}` | `{:multi, keys, multisig}` with `hash160/1`
  - `BSV.Tokens.OwnerAddress`: `{:address, string}` | `{:mpkh, hash}` for locking scripts
  - `Template.Stas`: `unlock_mpkh/3`, `unlock_from_signing_key/2` — auto-dispatch P2PKH vs P2MPKH
  - `Template.Stas3`: same dispatch pattern with spend_type
  - All STAS/STAS3 factories auto-dispatch via `Payment.resolve_signing_key/1`
  - Full backward compatibility — existing `private_key` field still works

- **STAS v3 Factory** — full protocol support
  - `build_stas_v3_locking_script/1`: freeze, confiscation, swap, note output
  - Shared `SpendType` and `ScriptFlags` extracted from STAS 3
  - Three-phase refactor for clean separation of concerns

- **STAS3 Full Operations**
  - Split, merge, confiscation, and redeem operations
  - Transfer-swap, swap-swap modes with remainder legs and frozen rejection
  - `Stas3Bundle`: automatic merge/split/transfer planning

### Test Coverage

- 920 tests, 0 failures
- 45 new P2MPKH integration tests covering template signing, factory integration, and type resolution

## v1.1.0 — 2026-03-20

- RFC 6979 security review findings addressed
- Initial token support release

## v1.0.0

- Initial release — full BSV SDK with primitives, script, transaction, wallet, message, auth, SPV, tokens, transports
