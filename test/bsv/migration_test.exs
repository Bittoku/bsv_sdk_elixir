defmodule BSV.MigrationTest do
  @moduledoc """
  Tests verifying backward compatibility with v0.1 (pre-security-patch) data.

  These tests simulate legacy ciphertexts encrypted with:
  - 32-byte GCM IV (legacy) vs 12-byte (current)
  - Raw ECDH x-coordinate as symmetric key (legacy) vs SHA-256(x-coord) (current)
  """
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, SymmetricKey}
  alias BSV.Wallet.{KeyDeriver, ProtoWallet}
  alias BSV.Wallet.Types.{Protocol, Counterparty, EncryptionArgs}

  @tag_size 16

  defp make_key(n) do
    raw = :crypto.hash(:sha256, <<n::256>>)
    {:ok, key} = PrivateKey.from_bytes(raw)
    key
  end

  describe "SymmetricKey legacy IV migration" do
    test "decrypt ciphertext encrypted with 32-byte IV" do
      key = SymmetricKey.new(:crypto.hash(:sha256, "test-key"))
      plaintext = "hello from v0.1"

      # Simulate legacy encryption with 32-byte IV
      legacy_iv = :crypto.strong_rand_bytes(32)
      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key.raw, legacy_iv, plaintext, <<>>, @tag_size, true)
      legacy_encrypted = legacy_iv <> ciphertext <> tag

      # Current decrypt should handle it
      assert {:ok, ^plaintext} = SymmetricKey.decrypt(key, legacy_encrypted)
    end

    test "decrypt ciphertext encrypted with 12-byte IV" do
      key = SymmetricKey.new(:crypto.hash(:sha256, "test-key"))
      plaintext = "hello from v0.2"

      {:ok, encrypted} = SymmetricKey.encrypt(key, plaintext)
      assert {:ok, ^plaintext} = SymmetricKey.decrypt(key, encrypted)
    end

    test "new encrypt uses 12-byte IV" do
      key = SymmetricKey.new(:crypto.hash(:sha256, "test-key"))
      {:ok, encrypted} = SymmetricKey.encrypt(key, "test")

      # 12 IV + at least 4 ciphertext + 16 tag = 32 minimum
      # vs 32 IV + 4 + 16 = 52 for legacy
      # With empty plaintext: 12 + 0 + 16 = 28 vs 32 + 0 + 16 = 48
      assert byte_size(encrypted) == 12 + 4 + @tag_size
    end

    test "wrong key still fails for both IV sizes" do
      key1 = SymmetricKey.new(:crypto.hash(:sha256, "key1"))
      key2 = SymmetricKey.new(:crypto.hash(:sha256, "key2"))

      {:ok, encrypted} = SymmetricKey.encrypt(key1, "secret")
      assert {:error, :decrypt_failed} = SymmetricKey.decrypt(key2, encrypted)

      # Also with legacy format
      legacy_iv = :crypto.strong_rand_bytes(32)
      {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key1.raw, legacy_iv, "secret", <<>>, @tag_size, true)
      legacy = legacy_iv <> ct <> tag
      assert {:error, :decrypt_failed} = SymmetricKey.decrypt(key2, legacy)
    end
  end

  describe "ECDH KDF migration in Message.Encrypted" do
    test "decrypt message encrypted with legacy KDF (raw x-coord)" do
      sender = make_key(1)
      recipient = make_key(2)
      recipient_pub = PrivateKey.to_public_key(recipient)

      # Encrypt with current code
      {:ok, encrypted} = BSV.Message.Encrypted.encrypt("new format", sender, recipient_pub)
      assert {:ok, "new format"} = BSV.Message.Encrypted.decrypt(encrypted, recipient)

      # Now simulate a legacy-encrypted message:
      # Build the same envelope but with raw x-coord as key and 32-byte IV
      key_id = :crypto.strong_rand_bytes(32)
      key_id_b64 = Base.encode64(key_id)
      invoice = "2-message encryption-#{key_id_b64}"

      {:ok, signing_priv} = PrivateKey.derive_child(sender, recipient_pub, invoice)
      {:ok, recipient_derived} = BSV.PublicKey.derive_child(recipient_pub, sender, invoice)
      {:ok, shared} = PrivateKey.derive_shared_secret(signing_priv, recipient_derived)

      <<_prefix::8, x_coord::binary-size(32)>> = shared.point
      legacy_key = SymmetricKey.new(x_coord)  # raw, no SHA-256

      # Encrypt with legacy 32-byte IV
      legacy_iv = :crypto.strong_rand_bytes(32)
      plaintext = "hello from v0.1"
      {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, legacy_key.raw, legacy_iv, plaintext, <<>>, @tag_size, true)
      legacy_ciphertext = legacy_iv <> ct <> tag

      version = <<0x42, 0x42, 0x10, 0x33>>
      sender_pub = PrivateKey.to_public_key(sender).point
      legacy_message = version <> sender_pub <> recipient_pub.point <> key_id <> legacy_ciphertext

      # Current decrypt should handle it via fallback
      assert {:ok, ^plaintext} = BSV.Message.Encrypted.decrypt(legacy_message, recipient)
    end
  end

  describe "ECDH KDF migration in ProtoWallet" do
    test "decrypt data encrypted with legacy KDF" do
      pk = make_key(42)
      wallet = ProtoWallet.from_private_key(pk)

      protocol = %Protocol{security_level: 2, protocol: "migration test"}
      counterparty = %Counterparty{type: :self}
      enc = %EncryptionArgs{protocol_id: protocol, key_id: "test1", counterparty: counterparty}

      # Encrypt with current code
      {:ok, encrypted} = ProtoWallet.encrypt(wallet, enc, "current data")
      assert {:ok, "current data"} = ProtoWallet.decrypt(wallet, enc, encrypted)

      # Encrypt with legacy key derivation
      {:ok, legacy_key} = KeyDeriver.derive_symmetric_key(
        wallet.key_deriver, protocol, "test1", counterparty, legacy: true
      )

      legacy_iv = :crypto.strong_rand_bytes(32)
      plaintext = "legacy data"
      {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, legacy_key.raw, legacy_iv, plaintext, <<>>, @tag_size, true)
      legacy_ciphertext = legacy_iv <> ct <> tag

      # ProtoWallet.decrypt should handle legacy data
      assert {:ok, ^plaintext} = ProtoWallet.decrypt(wallet, enc, legacy_ciphertext)
    end

    test "verify HMAC created with legacy KDF" do
      pk = make_key(42)
      wallet = ProtoWallet.from_private_key(pk)

      protocol = %Protocol{security_level: 2, protocol: "migration test"}
      counterparty = %Counterparty{type: :self}
      enc = %EncryptionArgs{protocol_id: protocol, key_id: "hmac1", counterparty: counterparty}

      # Create HMAC with current code
      {:ok, current_hmac} = ProtoWallet.create_hmac(wallet, enc, "data")
      assert {:ok, true} = ProtoWallet.verify_hmac(wallet, enc, "data", current_hmac)

      # Create HMAC with legacy key
      {:ok, legacy_key} = KeyDeriver.derive_symmetric_key(
        wallet.key_deriver, protocol, "hmac1", counterparty, legacy: true
      )
      legacy_hmac = BSV.Crypto.sha256_hmac("data", SymmetricKey.to_bytes(legacy_key))

      # verify_hmac should still accept legacy HMACs
      assert {:ok, true} = ProtoWallet.verify_hmac(wallet, enc, "data", legacy_hmac)
    end

    test "invalid HMAC rejected for both current and legacy" do
      pk = make_key(42)
      wallet = ProtoWallet.from_private_key(pk)

      protocol = %Protocol{security_level: 2, protocol: "migration test"}
      counterparty = %Counterparty{type: :self}
      enc = %EncryptionArgs{protocol_id: protocol, key_id: "hmac2", counterparty: counterparty}

      fake_hmac = :crypto.strong_rand_bytes(32)
      assert {:ok, false} = ProtoWallet.verify_hmac(wallet, enc, "data", fake_hmac)
    end
  end
end
