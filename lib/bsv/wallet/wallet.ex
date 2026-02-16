defmodule BSV.Wallet do
  @moduledoc """
  The wallet behaviour — defines the interface for BSV wallet operations.

  Core operations (implemented by ProtoWallet):
  - Key derivation (get_public_key)
  - Encryption/decryption
  - Signing/verification
  - HMAC creation/verification

  Transaction and certificate operations are defined but return
  `{:error, "not implemented"}` by default.
  """

  alias BSV.Wallet.Types.EncryptionArgs

  # === Key Operations ===

  @callback get_public_key(wallet :: struct(), opts :: keyword()) ::
              {:ok, BSV.PublicKey.t()} | {:error, String.t()}

  @callback encrypt(wallet :: struct(), enc :: EncryptionArgs.t(), plaintext :: binary()) ::
              {:ok, binary()} | {:error, term()}

  @callback decrypt(wallet :: struct(), enc :: EncryptionArgs.t(), ciphertext :: binary()) ::
              {:ok, binary()} | {:error, term()}

  @callback create_signature(
              wallet :: struct(),
              enc :: EncryptionArgs.t(),
              data :: binary(),
              hash_to_sign :: binary() | nil
            ) :: {:ok, binary()} | {:error, String.t()}

  @callback verify_signature(
              wallet :: struct(),
              enc :: EncryptionArgs.t(),
              data :: binary() | nil,
              hash_to_verify :: binary() | nil,
              signature :: binary(),
              opts :: keyword()
            ) :: {:ok, boolean()} | {:error, String.t()}

  @callback create_hmac(wallet :: struct(), enc :: EncryptionArgs.t(), data :: binary()) ::
              {:ok, binary()} | {:error, String.t()}

  @callback verify_hmac(
              wallet :: struct(),
              enc :: EncryptionArgs.t(),
              data :: binary(),
              hmac :: binary()
            ) :: {:ok, boolean()} | {:error, String.t()}
end
