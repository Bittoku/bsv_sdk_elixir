# BSV SDK for Elixir

A feature-complete Bitcoin SV SDK for Elixir, ported from the [Rust BSV SDK](https://github.com/bsv-sdk/bsv-sdk-rust).

## Features

- **Primitives** — keys, hashing, Base58, HD derivation
- **Script** — full interpreter, P2PKH, OP_RETURN, custom scripts
- **Transaction** — building, signing, BIP-143 sighash
- **Wallet** — BRC-42/43 key derivation, encryption, signing
- **Message** — BRC-78 ECIES encryption, BRC-77 signing
- **Auth** — BRC-31 certificates, field encryption
- **SPV** — BRC-74 merkle paths, BEEF parsing
- **Tokens** — STAS, STAS-BTG, DSTAS token protocol support
- **Transports** — ARC broadcaster, JungleBus queries

## Installation

Add to your `mix.exs`:

```elixir
def deps do
  [{:bsv_sdk, "~> 0.1.0"}]
end
```

## Quick Start

```elixir
# Generate a key pair
key = BSV.PrivateKey.generate()
pubkey = BSV.PrivateKey.to_public_key(key)
address = BSV.PublicKey.to_address(pubkey)

# Build a transaction
alias BSV.Transaction.{Builder, P2PKH}

tx = Builder.new()
|> Builder.add_input(txid, vout, satoshis, locking_script, P2PKH.unlock(key))
|> Builder.add_p2pkh_output(recipient_address, amount)
|> Builder.sign()

# Broadcast via ARC
client = BSV.ARC.Client.new(%BSV.ARC.Config{api_key: "your-key"})
{:ok, response} = BSV.ARC.Client.broadcast(client, tx)

# BRC-78 encrypted message
{:ok, ciphertext} = BSV.Message.Encrypted.encrypt(plaintext, sender_key, recipient_pubkey)
{:ok, plaintext} = BSV.Message.Encrypted.decrypt(ciphertext, recipient_key, sender_pubkey)

# STAS token issuance
alias BSV.Tokens.Factory.Stas
{:ok, tx} = Stas.build_issue_tx(config)
```

## Architecture

Layered design with zero framework dependencies:

- Pure Elixir core using OTP `:crypto` / `:public_key`
- `{:ok, result} | {:error, reason}` convention throughout
- Binary pattern matching for all protocol parsing
- Pipe-friendly APIs
- Comprehensive typespecs

## Test Suite

```bash
mix test           # 594 tests
mix test --cover   # ~91% coverage
mix dialyzer       # typespec verification
```

## Production Deployment

- Set `ERL_CRASH_DUMP=/dev/null` or start the VM with `+d` to prevent crash
  dumps from being written. Crash dumps can contain sensitive key material
  held in process memory.
- Ensure `erl_crash.dump` is in your `.gitignore` (included by default).

## License

MIT
