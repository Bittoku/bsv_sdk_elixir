# Changelog

## v1.2.0 — 2026-03-26

### New Features

- **P2MPKH (Pay-to-Multiple-Public-Key-Hash)** — m-of-n multisig ownership for STAS/DSTAS tokens
  - `BSV.Transaction.P2MPKH`: MultisigScript creation, serialization, MPKH (HASH160), lock/unlock
  - `BSV.Tokens.SigningKey`: `{:single, key}` | `{:multi, keys, multisig}` with `hash160/1`
  - `BSV.Tokens.OwnerAddress`: `{:address, string}` | `{:mpkh, hash}` for locking scripts
  - `Template.Stas`: `unlock_mpkh/3`, `unlock_from_signing_key/2` — auto-dispatch P2PKH vs P2MPKH
  - `Template.Dstas`: same dispatch pattern with spend_type
  - All STAS/DSTAS factories auto-dispatch via `Payment.resolve_signing_key/1`
  - Full backward compatibility — existing `private_key` field still works

- **STAS v3 Factory** — full protocol support
  - `build_stas_v3_locking_script/1`: freeze, confiscation, swap, note output
  - Shared `SpendType` and `ScriptFlags` extracted from dSTAS
  - Three-phase refactor for clean separation of concerns

- **DSTAS Full Operations**
  - Split, merge, confiscation, and redeem operations
  - Transfer-swap, swap-swap modes with remainder legs and frozen rejection
  - `DstasBundleFactory`: automatic merge/split/transfer planning

### Test Coverage

- 920 tests, 0 failures
- 45 new P2MPKH integration tests covering template signing, factory integration, and type resolution

## v1.1.0 — 2026-03-20

- RFC 6979 security review findings addressed
- Initial token support release

## v1.0.0

- Initial release — full BSV SDK with primitives, script, transaction, wallet, message, auth, SPV, tokens, transports
