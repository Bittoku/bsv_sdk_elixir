defmodule BSV.Message.Encrypted do
  @moduledoc """
  BRC-78 message encryption and decryption.

  Wire format:
  `version (4 bytes) || sender_pubkey (33 bytes) || recipient_pubkey (33 bytes) || key_id (32 bytes) || ciphertext`

  See: <https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0078.md>

  ## Migration Notice (v0.2)

  The symmetric key derivation was changed from raw ECDH x-coordinate to
  `SHA-256(x-coordinate)` for improved security. Decryption automatically
  falls back to the legacy derivation if the new key fails, ensuring
  backward compatibility with messages encrypted by v0.1.

  New encryptions always use the secure SHA-256 derivation.
  """

  alias BSV.{PrivateKey, PublicKey, SymmetricKey}

  @version <<0x42, 0x42, 0x10, 0x33>>
  @min_length 4 + 33 + 33 + 32 + 1

  @doc """
  Encrypt a message using the sender's private key and the recipient's public key.
  """
  @spec encrypt(binary(), PrivateKey.t(), PublicKey.t()) :: {:ok, binary()} | {:error, String.t()}
  def encrypt(message, %PrivateKey{} = sender, %PublicKey{} = recipient) do
    key_id = :crypto.strong_rand_bytes(32)
    key_id_b64 = Base.encode64(key_id)
    invoice_number = "2-message encryption-#{key_id_b64}"

    with {:ok, signing_priv} <- PrivateKey.derive_child(sender, recipient, invoice_number),
         {:ok, recipient_derived} <- PublicKey.derive_child(recipient, sender, invoice_number),
         {:ok, shared_secret} <- PrivateKey.derive_shared_secret(signing_priv, recipient_derived) do
      # Derive symmetric key from shared secret via SHA-256 (not raw x-coord)
      <<_prefix::8, x_coord::binary-size(32)>> = shared_secret.point
      derived_key = BSV.Crypto.sha256(x_coord)
      skey = SymmetricKey.new(derived_key)
      {:ok, ciphertext} = SymmetricKey.encrypt(skey, message)

      sender_pub = PrivateKey.to_public_key(sender).point
      recipient_pub = recipient.point

      {:ok, @version <> sender_pub <> recipient_pub <> key_id <> ciphertext}
    end
  end

  @doc """
  Decrypt a BRC-78 encrypted message using the recipient's private key.
  """
  @spec decrypt(binary(), PrivateKey.t()) :: {:ok, binary()} | {:error, String.t()}
  def decrypt(message, %PrivateKey{} = _recipient) when byte_size(message) < @min_length do
    {:error, "message too short: expected at least #{@min_length} bytes, got #{byte_size(message)} bytes"}
  end

  def decrypt(<<@version, sender_bytes::binary-size(33), recipient_bytes::binary-size(33),
                key_id::binary-size(32), ciphertext::binary>>, %PrivateKey{} = recipient) do
    actual_recipient = PrivateKey.to_public_key(recipient).point

    if not BSV.Crypto.secure_compare(recipient_bytes, actual_recipient) do
      {:error, "recipient public key mismatch"}
    else
      with {:ok, sender} <- PublicKey.from_bytes(sender_bytes) do
        key_id_b64 = Base.encode64(key_id)
        invoice_number = "2-message encryption-#{key_id_b64}"

        with {:ok, signing_pub} <- PublicKey.derive_child(sender, recipient, invoice_number),
             {:ok, recipient_derived} <- PrivateKey.derive_child(recipient, sender, invoice_number) do
          {:ok, shared_secret} = PrivateKey.derive_shared_secret(recipient_derived, signing_pub)

          <<_prefix::8, x_coord::binary-size(32)>> = shared_secret.point

          # Try new KDF (SHA-256) first, fall back to legacy (raw x-coord)
          derived_key = BSV.Crypto.sha256(x_coord)
          skey = SymmetricKey.new(derived_key)

          case SymmetricKey.decrypt(skey, ciphertext) do
            {:ok, _} = result ->
              result

            {:error, :decrypt_failed} ->
              # Legacy fallback: raw x-coordinate as key
              legacy_skey = SymmetricKey.new(x_coord)
              SymmetricKey.decrypt(legacy_skey, ciphertext)
          end
        end
      end
    end
  end

  def decrypt(<<version::binary-size(4), _::binary>>, %PrivateKey{}) do
    {:error, "message version mismatch: Expected #{Base.encode16(@version, case: :lower)}, received #{Base.encode16(version, case: :lower)}"}
  end
end
