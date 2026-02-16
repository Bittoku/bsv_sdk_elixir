# BSV Elixir SDK — Project Plan

## Overview

Feature-for-feature Elixir port of the BSV Rust SDK (`~/work/bsv-sdk-rust`), written using Elixir idioms and best practices. Designed for AI-enhanced workflows, platforms, and model training pipelines.

## Architecture

Layered design — lean core, optional Ash framework integration:

```
┌─────────────────────────────────┐
│  bsv_ash (optional)             │  Ash resources, actions, policies
│  Token, Wallet, Transaction     │  AI-discoverable, GraphQL-ready
├─────────────────────────────────┤
│  bsv_sdk (core)                 │  Pure Elixir, zero framework deps
│  Primitives, Script, TX, SPV    │  Structs, behaviours, protocols
└─────────────────────────────────┘
```

### Core SDK (`bsv_sdk`)
- Pure Elixir — no framework dependencies
- Structs, behaviours, protocols
- `{:ok, result} | {:error, reason}` convention
- Erlang `:crypto` / `:public_key` for cryptographic primitives
- Binary pattern matching for protocol parsing
- Publishable to Hex.pm independently

### Ash Layer (`bsv_ash`) — Phase 2
- Wraps core SDK types as Ash resources
- Declarative actions: issue, transfer, freeze, broadcast, etc.
- Built-in authorization policies
- AI agent introspection via Ash resource metadata
- GraphQL/JSON:API extensions
- Separate Hex package

## Rust SDK Inventory (what we're porting)

| Rust Crate | Lines | Tests | Elixir Module | Description |
|---|---|---|---|---|
| `bsv-primitives` | 3,371 | ~60 | `BSV.Primitives` | Keys, hashing, base58, HD derivation |
| `bsv-script` | 6,432 | ~76 | `BSV.Script` | Opcodes, script types, interpreter |
| `bsv-transaction` | 1,891 | ~30 | `BSV.Transaction` | Tx building, signing, templates |
| `bsv-wallet` | 2,602 | ~41 | `BSV.Wallet` | Key derivation, proto-wallet, serialization |
| `bsv-message` | 523 | ~11 | `BSV.Message` | BRC-78 encrypt, BRC-77 sign/verify |
| `bsv-auth` | 3,103 | ~23 | `BSV.Auth` | BRC-31 certs, peer auth, sessions |
| `bsv-spv` | 1,413 | ~22 | `BSV.SPV` | Merkle paths, BEEF parse/validate |
| `bsv-tokens` | 4,026 | ~62 | `BSV.Tokens` | STAS/DSTAS token protocol |
| `bsv-arc` | 728 | ~16 | `BSV.ARC` | ARC transaction broadcaster |
| `bsv-junglebus` | 533 | ~10 | `BSV.JungleBus` | GorillaPool chain queries |
| **Total** | **24,622** | **402** | | |

## Elixir Idioms & Adaptations

- **Structs + protocols** instead of Rust traits
- **Pattern matching** for script/binary parsing (Elixir's killer feature here)
- **`{:ok, result} | {:error, reason}`** tuples instead of `Result<T, E>`
- **Behaviours** for extensible interfaces (Broadcaster, Transport, UnlockingTemplate)
- **GenServer** for stateful components (wallet, subscription client)
- **`:crypto` / `:public_key`** OTP modules for ECDSA, SHA256, RIPEMD160, AES-GCM
- **ExUnit + StreamData** for property-based testing
- **ExDoc** for documentation, **Dialyxir** for typespecs
- **Tesla** or **Req** for HTTP clients (ARC, JungleBus)
- **WebSockex** or **Mint.WebSocket** for JungleBus subscriptions

## Phases

### Phase E1: Primitives
- `BSV.Crypto` — SHA256, RIPEMD160, Hash160, SHA256d
- `BSV.PrivateKey` — generation, WIF encode/decode
- `BSV.PublicKey` — derivation from private key, compressed/uncompressed
- `BSV.Address` — P2PKH address encode/decode, base58check
- `BSV.HD` — BIP-32 HD key derivation (master key, child derivation, paths)
- Leverage `:crypto.hash/2`, `:crypto.generate_key/2`, `:public_key` OTP modules

### Phase E2: Script
- `BSV.Script` — script struct, serialization, opcodes
- `BSV.Script.Parser` — binary pattern matching for script classification
- `BSV.Script.Builder` — construct standard script types (P2PKH, OP_RETURN, etc.)
- `BSV.Script.Interpreter` — full script interpreter with stack machine
- `BSV.Script.Opcodes` — opcode constants and helpers

### Phase E3: Transaction
- `BSV.Transaction` — tx struct, serialization (binary + hex)
- `BSV.Transaction.Input` / `BSV.Transaction.Output`
- `BSV.Transaction.Signer` — SIGHASH computation, ECDSA signing
- `BSV.Transaction.Builder` — pipe-friendly tx construction API
- `BSV.UnlockingTemplate` behaviour — P2PKH template as reference impl

### Phase E4: Wallet
- `BSV.Wallet.KeyDeriver` — BRC-42/BRC-43 key derivation
- `BSV.Wallet.ProtoWallet` — base wallet with key operations
- `BSV.Wallet` behaviour — wallet trait for signing, key derivation
- JSON + binary serialization

### Phase E5: Message
- `BSV.Message.Encrypt` — BRC-78 ECIES encryption/decryption
- `BSV.Message.Sign` — BRC-77 message signing/verification
- AES-GCM via `:crypto.crypto_one_time_aead/6`

### Phase E6: Auth
- `BSV.Auth.Certificate` — BRC-31 certificate struct, signing, verification
- `BSV.Auth.Peer` — peer authentication handshake
- `BSV.Auth.Session` — session management (GenServer)
- `BSV.Auth.Transport` behaviour

### Phase E7: SPV
- `BSV.SPV.MerklePath` — merkle path construction and verification
- `BSV.SPV.BEEF` — BEEF format parse/validate
- `BSV.SPV.Broadcaster` behaviour — transaction broadcasting interface

### Phase E8: Tokens
- `BSV.Tokens.Types` — TokenId, TokenScheme, ScriptType, etc.
- `BSV.Tokens.Script.Reader` — classify STAS/DSTAS locking scripts
- `BSV.Tokens.Script.Builder` — construct STAS/DSTAS locking scripts
- `BSV.Tokens.STAS` — STAS factories (issue, transfer, split, merge, redeem)
- `BSV.Tokens.DSTAS` — DSTAS factories (issue, freeze, unfreeze, swap)
- `BSV.Tokens.Bundle` — bundle planner and orchestration

### Phase E9: Transports
- `BSV.ARC` — ARC HTTP client, implements Broadcaster behaviour
- `BSV.JungleBus` — REST client for tx/address/block queries
- `BSV.JungleBus.Subscription` — WebSocket subscription client (GenServer)

### Phase E10: Ash Layer (separate project: `bsv_ash`)
- `BsvAsh.Token` — Ash resource wrapping BSV.Tokens
- `BsvAsh.Wallet` — Ash resource wrapping BSV.Wallet
- `BsvAsh.Transaction` — Ash resource wrapping BSV.Transaction
- Actions, policies, calculations
- GraphQL/JSON:API extensions

## Project Structure

```
~/work/bsv_sdk_elixir/
├── mix.exs
├── lib/
│   └── bsv/
│       ├── crypto.ex
│       ├── private_key.ex
│       ├── public_key.ex
│       ├── address.ex
│       ├── hd.ex
│       ├── script/
│       │   ├── script.ex
│       │   ├── opcodes.ex
│       │   ├── parser.ex
│       │   ├── builder.ex
│       │   └── interpreter.ex
│       ├── transaction/
│       │   ├── transaction.ex
│       │   ├── input.ex
│       │   ├── output.ex
│       │   ├── signer.ex
│       │   └── builder.ex
│       ├── wallet/
│       ├── message/
│       ├── auth/
│       ├── spv/
│       ├── tokens/
│       ├── arc/
│       └── junglebus/
├── test/
├── docs/
│   └── plan.md          ← this file
└── README.md
```

## Dependencies (minimal)

- `:crypto` / `:public_key` (OTP — zero external deps for core crypto)
- `jason` — JSON encoding/decoding
- `req` or `tesla` — HTTP client (for ARC, JungleBus)
- `websockex` or `mint_web_socket` — WebSocket (for JungleBus subscriptions)
- `stream_data` — property-based testing (dev/test only)
- `dialyxir` — typespec checking (dev only)
- `ex_doc` — documentation (dev only)

## Design Principles

1. **Lean core** — no framework deps in `bsv_sdk`
2. **Functional first** — pure functions where possible, GenServer only when state is needed
3. **Binary-native** — leverage Elixir's binary pattern matching for all protocol parsing
4. **Pipe-friendly** — APIs designed for `|>` composition
5. **AI-accessible** — clear module boundaries, introspectable via Ash layer
6. **Well-typed** — comprehensive typespecs for Dialyzer
7. **Well-documented** — ExDoc with examples on every public function

## Reference

- Rust SDK source: `~/work/bsv-sdk-rust/`
- STAS PRD: `~/work/bsv-sdk-rust/docs/stas-prd-final.md`
- Rust SDK plan: `~/.claude/plans/tingly-dancing-stonebraker.md`
