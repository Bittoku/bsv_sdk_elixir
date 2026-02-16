defmodule BSV.Message.EncryptedTest do
  use ExUnit.Case, async: true

  alias BSV.PrivateKey
  alias BSV.Message.Encrypted

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  describe "encrypt/decrypt round-trip" do
    test "basic round-trip" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      msg = <<1, 2, 4, 8, 16, 32>>
      {:ok, encrypted} = Encrypted.encrypt(msg, sender, recipient_pub)
      {:ok, decrypted} = Encrypted.decrypt(encrypted, recipient)
      assert decrypted == msg
    end

    test "empty message" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      {:ok, encrypted} = Encrypted.encrypt(<<>>, sender, recipient_pub)
      {:ok, decrypted} = Encrypted.decrypt(encrypted, recipient)
      assert decrypted == <<>>
    end

    test "large message" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      msg = :crypto.strong_rand_bytes(1024)
      {:ok, encrypted} = Encrypted.encrypt(msg, sender, recipient_pub)
      {:ok, decrypted} = Encrypted.decrypt(encrypted, recipient)
      assert decrypted == msg
    end
  end

  describe "decrypt errors" do
    test "wrong version" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      {:ok, encrypted} = Encrypted.encrypt(<<1, 2, 3>>, sender, recipient_pub)
      <<_::8, rest::binary>> = encrypted
      bad = <<0x01>> <> rest

      assert {:error, msg} = Encrypted.decrypt(bad, recipient)
      assert msg =~ "version mismatch"
    end

    test "wrong recipient" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)
      wrong = make_key(22)

      {:ok, encrypted} = Encrypted.encrypt(<<1, 2, 3>>, sender, recipient_pub)
      assert {:error, msg} = Encrypted.decrypt(encrypted, wrong)
      assert msg =~ "expects a recipient public key"
    end

    test "too short" do
      recipient = make_key(21)
      assert {:error, msg} = Encrypted.decrypt(<<0::80>>, recipient)
      assert msg =~ "too short"
    end
  end
end
