defmodule BSV.Message.SignedTest do
  use ExUnit.Case, async: true

  alias BSV.PrivateKey
  alias BSV.Message.Signed

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  describe "sign/verify for specific recipient" do
    test "round-trip" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      msg = <<1, 2, 4, 8, 16, 32>>
      {:ok, sig} = Signed.sign(msg, sender, recipient_pub)
      {:ok, valid} = Signed.verify(msg, sig, recipient)
      assert valid == true
    end

    test "tampered message fails" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      msg = <<1, 2, 4, 8, 16, 32>>
      {:ok, sig} = Signed.sign(msg, sender, recipient_pub)
      {:ok, valid} = Signed.verify(<<1, 2, 4, 8, 16, 64>>, sig, recipient)
      assert valid == false
    end
  end

  describe "sign/verify for anyone" do
    test "round-trip" do
      sender = make_key(15)

      msg = <<1, 2, 4, 8, 16, 32>>
      {:ok, sig} = Signed.sign(msg, sender)
      {:ok, valid} = Signed.verify(msg, sig)
      assert valid == true
    end

    test "tampered message fails" do
      sender = make_key(15)

      msg = <<1, 2, 4, 8, 16, 32>>
      {:ok, sig} = Signed.sign(msg, sender)
      {:ok, valid} = Signed.verify(<<1, 2, 4, 8, 16, 64>>, sig)
      assert valid == false
    end
  end

  describe "verify errors" do
    test "wrong version" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      {:ok, sig} = Signed.sign(<<1, 2, 3>>, sender, recipient_pub)
      <<_::8, rest::binary>> = sig
      bad = <<0x01>> <> rest

      assert {:error, msg} = Signed.verify(<<1, 2, 3>>, bad, recipient)
      assert msg =~ "version mismatch"
    end

    test "no verifier when required" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)

      {:ok, sig} = Signed.sign(<<1, 2, 3>>, sender, recipient_pub)
      assert {:error, msg} = Signed.verify(<<1, 2, 3>>, sig)
      assert msg =~ "specific recipient private key"
    end

    test "wrong verifier" do
      sender = make_key(15)
      recipient = make_key(21)
      recipient_pub = PrivateKey.to_public_key(recipient)
      wrong = make_key(22)

      {:ok, sig} = Signed.sign(<<1, 2, 3>>, sender, recipient_pub)
      assert {:error, msg} = Signed.verify(<<1, 2, 3>>, sig, wrong)
      assert msg =~ "recipient public key mismatch"
    end

    test "too short" do
      assert {:error, _} = Signed.verify(<<>>, <<0, 1>>, nil)
    end
  end
end
