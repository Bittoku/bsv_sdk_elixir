defmodule BSV.Auth.CertificateTest do
  use ExUnit.Case, async: true

  alias BSV.PrivateKey
  alias BSV.Auth.Certificate
  alias BSV.Wallet.ProtoWallet

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  defp make_cert do
    subject = PrivateKey.to_public_key(make_key(42))
    certifier = PrivateKey.to_public_key(make_key(69))

    %Certificate{
      cert_type: Base.encode64(:crypto.strong_rand_bytes(32)),
      serial_number: Base.encode64(:crypto.strong_rand_bytes(32)),
      subject: subject,
      certifier: certifier,
      fields: %{"name" => "Alice", "email" => "alice@example.com"}
    }
  end

  describe "to_binary/from_binary" do
    test "round-trip without signature" do
      cert = make_cert()
      {:ok, bin} = Certificate.to_binary(cert, false)
      {:ok, decoded} = Certificate.from_binary(bin)
      assert decoded.cert_type == cert.cert_type
      assert decoded.serial_number == cert.serial_number
      assert decoded.subject.point == cert.subject.point
      assert decoded.certifier.point == cert.certifier.point
      assert decoded.fields == cert.fields
      assert decoded.signature == <<>>
    end

    test "round-trip with signature" do
      cert = make_cert()
      cert = %{cert | signature: :crypto.strong_rand_bytes(71)}
      {:ok, bin} = Certificate.to_binary(cert, true)
      {:ok, decoded} = Certificate.from_binary(bin)
      assert decoded.signature == cert.signature
    end

    test "fields are sorted deterministically" do
      cert = make_cert()
      cert2 = %{cert | fields: %{"zebra" => "z", "alpha" => "a"}}
      {:ok, bin1} = Certificate.to_binary(cert2, false)
      {:ok, bin2} = Certificate.to_binary(cert2, false)
      assert bin1 == bin2
    end
  end

  describe "sign/verify" do
    test "sign and verify round-trip" do
      certifier_key = make_key(69)
      wallet = ProtoWallet.from_private_key(certifier_key)

      cert = make_cert()
      {:ok, signed} = Certificate.sign(cert, wallet)
      assert byte_size(signed.signature) > 0
      assert signed.certifier.point == PrivateKey.to_public_key(certifier_key).point

      {:ok, valid} = Certificate.verify(signed)
      assert valid == true
    end

    test "cannot sign already signed certificate" do
      wallet = ProtoWallet.from_private_key(make_key(69))
      cert = make_cert()
      {:ok, signed} = Certificate.sign(cert, wallet)
      assert {:error, "certificate already signed"} = Certificate.sign(signed, wallet)
    end

    test "verify unsigned certificate fails" do
      cert = make_cert()
      assert {:error, "certificate not signed"} = Certificate.verify(cert)
    end

    test "tampered certificate fails verification" do
      wallet = ProtoWallet.from_private_key(make_key(69))
      cert = make_cert()
      {:ok, signed} = Certificate.sign(cert, wallet)
      tampered = %{signed | fields: Map.put(signed.fields, "name", "Bob")}
      {:ok, valid} = Certificate.verify(tampered)
      assert valid == false
    end
  end

  describe "get_encryption_details" do
    test "with serial number" do
      {proto, key_id} = Certificate.get_encryption_details("name", "serial123")
      assert proto.security_level == 2
      assert proto.protocol == "certificate field encryption"
      assert key_id == "serial123 name"
    end

    test "without serial number" do
      {_proto, key_id} = Certificate.get_encryption_details("name", "")
      assert key_id == "name"
    end
  end
end
