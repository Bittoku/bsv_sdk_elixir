defmodule BSV.Auth.VerifiableCertificateTest do
  use ExUnit.Case, async: true

  alias BSV.Auth.{Certificate, VerifiableCertificate}
  alias BSV.Wallet.ProtoWallet
  alias BSV.PrivateKey

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  test "new creates struct with empty decrypted_fields" do
    cert = %Certificate{
      cert_type: "test",
      serial_number: "123",
      subject: ProtoWallet.identity_key(ProtoWallet.from_private_key(make_key(1))),
      certifier: ProtoWallet.identity_key(ProtoWallet.from_private_key(make_key(2))),
      fields: %{}
    }
    vc = VerifiableCertificate.new(cert, %{"a" => "b"})
    assert vc.certificate == cert
    assert vc.keyring == %{"a" => "b"}
    assert vc.decrypted_fields == %{}
  end

  test "decrypt_fields with empty keyring returns error" do
    cert = %Certificate{
      cert_type: "test",
      serial_number: "123",
      subject: ProtoWallet.identity_key(ProtoWallet.from_private_key(make_key(1))),
      certifier: ProtoWallet.identity_key(ProtoWallet.from_private_key(make_key(2))),
      fields: %{}
    }
    vc = VerifiableCertificate.new(cert, %{})
    wallet = ProtoWallet.from_private_key(make_key(3))
    assert {:error, msg} = VerifiableCertificate.decrypt_fields(vc, wallet)
    assert msg =~ "keyring is required"
  end

  test "verify delegates to Certificate.verify" do
    cert = %Certificate{
      cert_type: "test",
      serial_number: "123",
      subject: ProtoWallet.identity_key(ProtoWallet.from_private_key(make_key(1))),
      certifier: ProtoWallet.identity_key(ProtoWallet.from_private_key(make_key(2))),
      fields: %{}
    }
    vc = VerifiableCertificate.new(cert, %{"a" => "b"})
    # Unsigned cert - verify should return false or error
    result = VerifiableCertificate.verify(vc)
    assert match?({:ok, false}, result) or match?({:error, _}, result)
  end
end
