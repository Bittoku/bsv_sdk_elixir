defmodule BSV do
  @moduledoc """
  BSV SDK for Elixir — a feature-complete Bitcoin SV toolkit.

  ## Modules

  ### Primitives
  - `BSV.Crypto` — SHA256, RIPEMD160, Hash160, SHA256d
  - `BSV.PrivateKey` — key generation, WIF encode/decode, signing
  - `BSV.PublicKey` — derivation, compression, point arithmetic
  - `BSV.Base58` — Base58Check encode/decode
  - `BSV.ChainHash` — 32-byte transaction/block hash wrapper

  ### Script
  - `BSV.Script` — script struct, serialization, classification
  - `BSV.Script.Address` — P2PKH address handling
  - `BSV.Script.Opcodes` — opcode constants
  - `BSV.Script.Interpreter` — full script interpreter
  - `BSV.Script.ScriptNum` — Bitcoin script number encoding

  ### Transaction
  - `BSV.Transaction` — transaction struct, serialization
  - `BSV.Transaction.Builder` — pipe-friendly transaction construction
  - `BSV.Transaction.P2PKH` — P2PKH signing template
  - `BSV.Transaction.Sighash` — BIP-143 sighash computation

  ### Wallet
  - `BSV.Wallet` — wallet behaviour
  - `BSV.Wallet.KeyDeriver` — BRC-42/43 key derivation
  - `BSV.Wallet.ProtoWallet` — base wallet implementation

  ### Message
  - `BSV.Message.Encrypted` — BRC-78 ECIES encryption
  - `BSV.Message.Signed` — BRC-77 message signing

  ### Auth
  - `BSV.Auth.Certificate` — BRC-31 certificates
  - `BSV.Auth.MasterCertificate` — field encryption, keyring
  - `BSV.Auth.Nonce` — HMAC-based nonce

  ### SPV
  - `BSV.SPV.MerklePath` — BRC-74 merkle paths
  - `BSV.SPV.Beef` — BEEF container parsing

  ### Tokens (STAS/DSTAS)
  - `BSV.Tokens` — token operations facade
  - `BSV.Tokens.Scheme` — token scheme definition
  - `BSV.Tokens.Script.Reader` — script classification
  - `BSV.Tokens.Factory.Stas` — STAS transaction factories
  - `BSV.Tokens.Factory.Dstas` — DSTAS transaction factories
  - `BSV.Tokens.Lineage` — off-chain lineage validation

  ### Transports
  - `BSV.ARC.Client` — ARC transaction broadcaster
  - `BSV.JungleBus.Client` — JungleBus chain queries
  """
end
