defmodule BSV.Auth.MasterCertificateTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey}
  alias BSV.Auth.{Certificate, MasterCertificate}
  alias BSV.Wallet.ProtoWallet
  alias BSV.Wallet.Types.Counterparty

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  defp certifier_wallet, do: ProtoWallet.from_private_key(make_key(69))
  defp subject_wallet, do: ProtoWallet.from_private_key(make_key(42))
  defp verifier_wallet, do: ProtoWallet.from_private_key(make_key(99))

  defp plain_fields, do: %{"name" => "Alice", "email" => "alice@example.com"}

  describe "create_certificate_fields" do
    test "encrypts fields and generates keyring" do
      wallet = certifier_wallet()
      subject_pub = ProtoWallet.identity_key(subject_wallet())
      cp = %Counterparty{type: :other, public_key: subject_pub}

      {:ok, enc_fields, keyring} = MasterCertificate.create_certificate_fields(wallet, cp, plain_fields())
      assert map_size(enc_fields) == 2
      assert map_size(keyring) == 2
      assert Map.has_key?(enc_fields, "name")
      assert Map.has_key?(keyring, "name")
      # Encrypted values are base64
      assert {:ok, _} = Base.decode64(enc_fields["name"])
    end
  end

  describe "new/2" do
    test "validates keyring covers all fields" do
      cert = %Certificate{
        cert_type: Base.encode64(:crypto.strong_rand_bytes(32)),
        serial_number: Base.encode64(:crypto.strong_rand_bytes(32)),
        subject: ProtoWallet.identity_key(subject_wallet()),
        certifier: ProtoWallet.identity_key(certifier_wallet()),
        fields: %{"name" => "enc", "email" => "enc"}
      }

      assert {:error, msg} = MasterCertificate.new(cert, %{"name" => "key"})
      assert msg =~ "Missing key for field"
    end

    test "rejects empty keyring" do
      cert = %Certificate{
        cert_type: Base.encode64(:crypto.strong_rand_bytes(32)),
        serial_number: Base.encode64(:crypto.strong_rand_bytes(32)),
        subject: ProtoWallet.identity_key(subject_wallet()),
        certifier: ProtoWallet.identity_key(certifier_wallet()),
        fields: %{"name" => "enc"}
      }

      assert {:error, "missing master keyring"} = MasterCertificate.new(cert, %{})
    end
  end

  describe "full certificate lifecycle" do
    test "issue, decrypt, create verifier keyring, verify" do
      certifier_w = certifier_wallet()
      subject_w = subject_wallet()
      verifier_w = verifier_wallet()

      subject_pub = ProtoWallet.identity_key(subject_w)
      certifier_pub = ProtoWallet.identity_key(certifier_w)
      verifier_pub = ProtoWallet.identity_key(verifier_w)

      subject_cp = %Counterparty{type: :other, public_key: subject_pub}
      certifier_cp = %Counterparty{type: :other, public_key: certifier_pub}
      verifier_cp = %Counterparty{type: :other, public_key: verifier_pub}

      # 1. Certifier creates encrypted fields
      {:ok, enc_fields, master_keyring} =
        MasterCertificate.create_certificate_fields(certifier_w, subject_cp, plain_fields())

      # 2. Create and sign certificate
      cert = %Certificate{
        cert_type: Base.encode64(:crypto.strong_rand_bytes(32)),
        serial_number: Base.encode64(:crypto.strong_rand_bytes(32)),
        subject: subject_pub,
        certifier: certifier_pub,
        fields: enc_fields
      }

      {:ok, signed} = Certificate.sign(cert, certifier_w)
      {:ok, true} = Certificate.verify(signed)

      # 3. Subject decrypts fields with master keyring
      #    Master keyring was encrypted by certifier for subject, so subject wallet + certifier counterparty
      {:ok, decrypted} =
        MasterCertificate.decrypt_fields(subject_w, master_keyring, signed.fields, certifier_cp)
      assert decrypted["name"] == "Alice"
      assert decrypted["email"] == "alice@example.com"

      # 4. Subject creates keyring for verifier (reveal only "name")
      #    The subject wallet re-encrypts revelation keys for the verifier
      #    First, subject needs to decrypt master keyring (encrypted by certifier for subject)
      {:ok, verifier_keyring} =
        MasterCertificate.create_keyring_for_verifier(
          subject_w, certifier_cp, verifier_cp,
          signed.fields, ["name"], master_keyring, signed.serial_number
        )

      assert map_size(verifier_keyring) == 1
      assert Map.has_key?(verifier_keyring, "name")

      # 5. Verifier decrypts revealed fields
      vc = BSV.Auth.VerifiableCertificate.new(signed, verifier_keyring)
      {:ok, revealed, _vc2} = BSV.Auth.VerifiableCertificate.decrypt_fields(vc, verifier_w)
      assert revealed["name"] == "Alice"
      refute Map.has_key?(revealed, "email")
    end
  end
end
