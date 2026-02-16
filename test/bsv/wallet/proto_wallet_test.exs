defmodule BSV.Wallet.ProtoWalletTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey}
  alias BSV.Wallet.ProtoWallet
  alias BSV.Wallet.Types.{Protocol, Counterparty, EncryptionArgs}

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  defp test_protocol, do: %Protocol{security_level: 0, protocol: "testprotocol"}

  defp test_enc_args(counterparty) do
    %EncryptionArgs{
      protocol_id: test_protocol(),
      key_id: "test-key-1",
      counterparty: counterparty
    }
  end

  describe "identity_key/1" do
    test "returns correct public key" do
      pk = make_key(42)
      pw = ProtoWallet.from_private_key(pk)
      expected = PrivateKey.to_public_key(pk)
      assert ProtoWallet.identity_key(pw).point == expected.point
    end
  end

  describe "get_public_key/2" do
    test "returns identity key" do
      pw = ProtoWallet.from_private_key(make_key(42))
      assert {:ok, %PublicKey{}} = BSV.Wallet.ProtoWallet.get_public_key(pw, identity_key: true)
    end

    test "returns derived key" do
      pw = ProtoWallet.from_private_key(make_key(42))
      enc = test_enc_args(%Counterparty{type: :self})
      assert {:ok, %PublicKey{}} = ProtoWallet.get_public_key(pw, encryption_args: enc)
    end
  end

  describe "encrypt/decrypt" do
    test "roundtrip with self" do
      pw = ProtoWallet.from_private_key(make_key(42))
      plaintext = "Hello, BSV!"
      enc = test_enc_args(%Counterparty{type: :self})

      {:ok, ciphertext} = ProtoWallet.encrypt(pw, enc, plaintext)
      assert ciphertext != plaintext
      {:ok, decrypted} = ProtoWallet.decrypt(pw, enc, ciphertext)
      assert decrypted == plaintext
    end

    test "roundtrip between counterparties" do
      alice = ProtoWallet.from_private_key(make_key(42))
      bob = ProtoWallet.from_private_key(make_key(69))
      plaintext = "Secret message"

      alice_enc = test_enc_args(%Counterparty{type: :other, public_key: ProtoWallet.identity_key(bob)})
      {:ok, ciphertext} = ProtoWallet.encrypt(alice, alice_enc, plaintext)

      bob_enc = test_enc_args(%Counterparty{type: :other, public_key: ProtoWallet.identity_key(alice)})
      {:ok, decrypted} = ProtoWallet.decrypt(bob, bob_enc, ciphertext)
      assert decrypted == plaintext
    end
  end

  describe "create_signature/verify_signature" do
    test "sign and verify" do
      pw = ProtoWallet.from_private_key(make_key(42))
      data = "Sign this data"
      enc = test_enc_args(%Counterparty{type: :anyone})

      {:ok, signature} = ProtoWallet.create_signature(pw, enc, data, nil)
      assert is_binary(signature)

      {:ok, valid} = ProtoWallet.verify_signature(pw, enc, data, nil, signature, for_self: true)
      assert valid == true
    end
  end

  describe "create_hmac/verify_hmac" do
    test "create and verify" do
      pw = ProtoWallet.from_private_key(make_key(42))
      data = "HMAC this data"
      enc = test_enc_args(%Counterparty{type: :self})

      {:ok, hmac} = ProtoWallet.create_hmac(pw, enc, data)
      assert byte_size(hmac) == 32

      {:ok, valid} = ProtoWallet.verify_hmac(pw, enc, data, hmac)
      assert valid == true
    end

    test "invalid hmac fails" do
      pw = ProtoWallet.from_private_key(make_key(42))
      enc = test_enc_args(%Counterparty{type: :self})

      {:ok, valid} = ProtoWallet.verify_hmac(pw, enc, "some data", <<0::256>>)
      assert valid == false
    end
  end

  describe "anyone wallet" do
    test "works" do
      pw = ProtoWallet.anyone()
      assert {:ok, %PublicKey{}} = ProtoWallet.get_public_key(pw, identity_key: true)
    end
  end
end
