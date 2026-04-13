# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`bsv_sdk` — a pure-Elixir Bitcoin SV SDK ported from the Rust BSV SDK. Zero framework dependencies; uses OTP `:crypto` and `:public_key` for cryptographic primitives. Hex package name: `bsv_sdk` (current version in `mix.exs`, currently 1.4.0).

## Common Commands

```bash
mix deps.get                         # fetch dependencies
mix compile                          # compile
mix format                           # format (uses .formatter.exs)
mix test                             # run full test suite
mix test --cover                     # with coverage
mix test test/bsv/tokens/stas_test.exs           # single file
mix test test/bsv/tokens/stas_test.exs:42        # single test at line 42
mix test --only tag_name                         # tag-filtered run
mix dialyzer                         # typespec / static analysis (plt includes :jason, :req)
mix docs                             # generate ex_doc HTML under doc/
```

There is no separate lint step — `mix format` + `mix dialyzer` cover style and typing.

## Architecture

The SDK is layered. Higher layers depend only on lower layers, and each layer uses `{:ok, result} | {:error, reason}` for fallible operations. Raising variants exist only in builder-style convenience modules (e.g. `BSV.Transaction.Builder`). Binary pattern matching is used throughout for protocol parsing — avoid introducing intermediate parsers.

Layer map (all under `lib/bsv/`):

1. **Primitives** — `crypto.ex`, `private_key.ex`, `public_key.ex`, `key_pair.ex`, `base58.ex`, `chain_hash.ex`, `var_int.ex`, `symmetric_key.ex`, `ext_key.ex`, `mnemonic.ex`, `block.ex`, `block_header.ex`. Pure; no dependencies outside OTP.
2. **Script** (`lib/bsv/script/`) — `script.ex`, `opcodes.ex`, `script_num.ex`, `address.ex`, `interpreter.ex`. Full script interpreter plus standard template helpers.
3. **Transaction** (`lib/bsv/transaction/`) — `transaction.ex`, `input.ex`, `output.ex`, `builder.ex`, `sighash.ex` (BIP-143), `template.ex`, `p2pkh.ex`, `p2mpkh.ex`. `Builder` is the pipe-friendly entry point.
4. **Wallet / Message / Auth / SPV** — BRC-31/42/43/74/77/78 implementations. See module groups in `mix.exs` `docs/groups_for_modules` for the authoritative layer mapping.
5. **Tokens** (`lib/bsv/tokens/`) — the largest subsystem; see below.
6. **Transports** — `lib/bsv/arc/` (ARC broadcaster) and `lib/bsv/junglebus/` (JungleBus queries). These are the only network-touching modules and use `:req`.

### Tokens subsystem (critical reading before editing)

Three parallel token protocols are supported: **STAS** (legacy), **STAS-BTG**, and **STAS 3** (a.k.a. STAS v3 / STAS3 — note the rename in `CHANGELOG.md`; older docs may say "dSTAS/DSTAS"). Each protocol has three layers:

- `tokens/script/<name>_builder.ex` — builds the locking/unlocking scripts
- `tokens/template/<name>.ex` — signing templates; for STAS/STAS3 these auto-dispatch between P2PKH and P2MPKH via `Template.*.unlock_from_signing_key/2`
- `tokens/factory/<name>.ex` — high-level transaction factories (issue, transfer, split, merge, redeem, freeze/swap for STAS3)

Cross-cutting types live at `tokens/` root:

- `tokens.ex` — public facade with `defdelegate` into Reader + BTG factory
- `scheme.ex` — `Scheme` + `Authority` (m-of-n governance)
- `signing_key.ex` — `{:single, key} | {:multi, keys, multisig}` (P2MPKH support)
- `owner_address.ex` — `{:address, string} | {:mpkh, hash}`
- `spend_type.ex`, `script_flags.ex` — **shared** between STAS and STAS 3; extracted during the STAS 3 refactor. Do not duplicate these in protocol-specific modules.
- `lineage.ex`, `proof.ex`, `token_id.ex`, `script_type.ex`
- `bundle/stas3_bundle.ex` — automatic merge/split/transfer planning for STAS3

When adding features to a token protocol, the Builder → Template → Factory order is load-bearing: scripts must be expressible in the Builder before the Template can sign them, and the Factory composes both. Changes that affect `SpendType`/`ScriptFlags` affect both STAS and STAS 3 — run both test directories.

### STAS protocol reference material

Detailed opcode-level analysis of the on-chain STAS templates lives **outside this repo** at `~/.claude/memory/stas-protocol/` (see user global CLAUDE.md for the file list). When modifying `tokens/script/*_builder.ex` or debugging a locking-script mismatch, consult those disassemblies (`STAS_Legacy.asm`, `STAS-20.asm`, `STAS-50.asm`, `STAS-789.asm`) as the source of truth — the Elixir builders are ports of those scripts.

## Testing conventions

- Tests mirror `lib/` layout under `test/bsv/`. Keep new tests colocated with the module under test.
- `stream_data` is available for property-based tests; `bypass` is available for ARC / JungleBus HTTP client tests (`:test` only).
- `test/bsv/migration_test.exs` guards against accidental breaking changes in cross-version serialization — update deliberately.
- The README claims 594 tests / ~91% coverage; `CHANGELOG.md` (v1.2.0) reports 920 tests after P2MPKH landed. Trust the actual `mix test` output, not either number.

## Security-sensitive notes

- RFC 6979 deterministic signing is used for ECDSA; `SECURITY-REVIEW-RFC6979.md` and `SECURITY-AUDIT.md` at the repo root document prior review findings. Treat any change to signing / nonce generation as security-sensitive and re-read those docs first.
- Never write to `erl_crash.dump` in production — it may contain private key material. `.gitignore` excludes it; the README documents `ERL_CRASH_DUMP=/dev/null` / VM `+d` as mitigations.

## Conventions

- `{:ok, _} | {:error, _}` for anything that can fail; raising variants are only for explicit `Builder`-style convenience paths and must be documented as "Raises on error".
- Every public function has a `@spec` and a one-line `@doc`. Module docs are short (`@moduledoc "..."`); see `lib/bsv/transaction/builder.ex` for the house style.
- Prefer binary pattern matching over `:binary.part/3` style extraction.
- Aliases are grouped: `alias BSV.Transaction.{Output, P2PKH}`.
- Do **not** add AI attribution (`Co-Authored-By: Claude`, etc.) to commit messages.
