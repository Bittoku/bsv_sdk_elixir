defmodule BSV.Wallet.KeyDeriverTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey}
  alias BSV.Wallet.KeyDeriver
  alias BSV.Wallet.Types.{Protocol, Counterparty}

  defp make_key(val) do
    raw = <<0::248, val::8>>
    {:ok, pk} = PrivateKey.from_bytes(raw)
    pk
  end

  defp test_protocol, do: %Protocol{security_level: 0, protocol: "testprotocol"}

  defp root_kd, do: KeyDeriver.new(make_key(42))
  defp counterparty_pub, do: PrivateKey.to_public_key(make_key(69))
  defp anyone_pub, do: KeyDeriver.anyone_public_key()

  describe "identity_key/1" do
    test "returns root public key" do
      root = make_key(42)
      kd = KeyDeriver.new(root)
      expected = PrivateKey.to_public_key(root)
      assert KeyDeriver.identity_key(kd).point == expected.point
    end

    test "identity_key_hex matches hex encoding" do
      root = make_key(42)
      kd = KeyDeriver.new(root)
      expected = Base.encode16(PrivateKey.to_public_key(root).point, case: :lower)
      assert KeyDeriver.identity_key_hex(kd) == expected
    end
  end

  describe "compute_invoice_number/2" do
    test "produces correct format" do
      assert {:ok, "0-testprotocol-12345"} =
               KeyDeriver.compute_invoice_number(test_protocol(), "12345")
    end

    test "rejects empty key ID" do
      assert {:error, "key IDs must be 1 character or more"} =
               KeyDeriver.compute_invoice_number(test_protocol(), "")
    end

    test "rejects long key ID" do
      assert {:error, _} =
               KeyDeriver.compute_invoice_number(test_protocol(), String.duplicate("x", 801))
    end

    test "rejects invalid security level" do
      assert {:error, "protocol security level must be 0, 1, or 2"} =
               KeyDeriver.compute_invoice_number(%Protocol{security_level: -3, protocol: "otherwise valid"}, "key")
    end

    test "rejects double spaces" do
      assert {:error, _} =
               KeyDeriver.compute_invoice_number(%Protocol{security_level: 2, protocol: "double  space"}, "key")
    end

    test "rejects empty protocol" do
      assert {:error, "protocol names must be 5 characters or more"} =
               KeyDeriver.compute_invoice_number(%Protocol{security_level: 0, protocol: ""}, "key")
    end

    test "rejects long protocol" do
      assert {:error, "protocol names must be 400 characters or less"} =
               KeyDeriver.compute_invoice_number(%Protocol{security_level: 0, protocol: "long" <> String.duplicate("x", 400)}, "key")
    end

    test "rejects redundant protocol suffix" do
      assert {:error, _} =
               KeyDeriver.compute_invoice_number(%Protocol{security_level: 2, protocol: "redundant protocol protocol"}, "key")
    end

    test "rejects unicode characters" do
      assert {:error, _} =
               KeyDeriver.compute_invoice_number(%Protocol{security_level: 2, protocol: "üñî√é®sål ©0på"}, "key")
    end
  end

  describe "normalize_counterparty/2" do
    test "self returns root pub key" do
      kd = root_kd()
      {:ok, pk} = KeyDeriver.normalize_counterparty(kd, %Counterparty{type: :self})
      assert pk.point == KeyDeriver.identity_key(kd).point
    end

    test "anyone returns anyone key" do
      kd = root_kd()
      {:ok, pk} = KeyDeriver.normalize_counterparty(kd, %Counterparty{type: :anyone})
      assert pk.point == anyone_pub().point
    end

    test "other returns provided key" do
      kd = root_kd()
      cp = counterparty_pub()
      {:ok, pk} = KeyDeriver.normalize_counterparty(kd, %Counterparty{type: :other, public_key: cp})
      assert pk.point == cp.point
    end

    test "other without key errors" do
      kd = root_kd()
      assert {:error, _} = KeyDeriver.normalize_counterparty(kd, %Counterparty{type: :other})
    end

    test "uninitialized errors" do
      kd = root_kd()
      assert {:error, _} = KeyDeriver.normalize_counterparty(kd, %Counterparty{type: :uninitialized})
    end
  end

  describe "derive_public_key/5" do
    test "derives for counterparty" do
      kd = root_kd()
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      assert {:ok, %PublicKey{}} = KeyDeriver.derive_public_key(kd, test_protocol(), "12345", cp, false)
    end

    test "derives for self" do
      kd = root_kd()
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      assert {:ok, %PublicKey{}} = KeyDeriver.derive_public_key(kd, test_protocol(), "12345", cp, true)
    end

    test "derives as anyone" do
      kd = KeyDeriver.new(nil)
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      assert {:ok, %PublicKey{}} = KeyDeriver.derive_public_key(kd, test_protocol(), "12345", cp, false)
    end
  end

  describe "derive_private_key/4" do
    test "derives a private key" do
      kd = root_kd()
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      assert {:ok, %PrivateKey{}} = KeyDeriver.derive_private_key(kd, test_protocol(), "12345", cp)
    end
  end

  describe "derive_symmetric_key/4" do
    test "derives a symmetric key for counterparty" do
      kd = root_kd()
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      assert {:ok, sk} = KeyDeriver.derive_symmetric_key(kd, test_protocol(), "12345", cp)
      assert byte_size(sk.raw) == 32
    end

    test "known test vector matches Rust" do
      kd = root_kd()
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      {:ok, sk} = KeyDeriver.derive_symmetric_key(kd, test_protocol(), "12345", cp)
      assert Base.encode16(sk.raw, case: :lower) ==
               "4ce8e868f2006e3fa8fc61ea4bc4be77d397b412b44b4dca047fb7ec3ca7cfd8"
    end

    test "derives with anyone counterparty" do
      kd = root_kd()
      cp = %Counterparty{type: :anyone}
      assert {:ok, sk} = KeyDeriver.derive_symmetric_key(kd, test_protocol(), "12345", cp)
      assert byte_size(sk.raw) == 32
    end
  end

  describe "reveal_counterparty_secret/2" do
    test "cannot reveal for self" do
      kd = root_kd()
      assert {:error, "counterparty secrets cannot be revealed for counterparty=self"} =
               KeyDeriver.reveal_counterparty_secret(kd, %Counterparty{type: :self})
    end

    test "cannot reveal for own public key" do
      kd = root_kd()
      own_pub = KeyDeriver.identity_key(kd)
      assert {:error, "counterparty secrets cannot be revealed if counterparty key is self"} =
               KeyDeriver.reveal_counterparty_secret(kd, %Counterparty{type: :other, public_key: own_pub})
    end

    test "reveals for other counterparty" do
      kd = root_kd()
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      assert {:ok, %PublicKey{}} = KeyDeriver.reveal_counterparty_secret(kd, cp)
    end

    test "matches manual ECDH" do
      root = make_key(42)
      kd = KeyDeriver.new(root)
      cp_pub = counterparty_pub()
      {:ok, shared} = KeyDeriver.reveal_counterparty_secret(kd, %Counterparty{type: :other, public_key: cp_pub})
      {:ok, expected} = PrivateKey.derive_shared_secret(root, cp_pub)
      assert shared.point == expected.point
    end
  end

  describe "reveal_specific_secret/4" do
    test "produces non-empty secret" do
      kd = root_kd()
      cp = %Counterparty{type: :other, public_key: counterparty_pub()}
      assert {:ok, secret} = KeyDeriver.reveal_specific_secret(kd, cp, test_protocol(), "12345")
      assert byte_size(secret) == 32
    end

    test "matches manual computation" do
      root = make_key(42)
      kd = KeyDeriver.new(root)
      cp_pub = counterparty_pub()
      cp = %Counterparty{type: :other, public_key: cp_pub}
      proto = test_protocol()
      key_id = "12345"

      {:ok, secret} = KeyDeriver.reveal_specific_secret(kd, cp, proto, key_id)

      {:ok, shared} = PrivateKey.derive_shared_secret(root, cp_pub)
      {:ok, inv} = KeyDeriver.compute_invoice_number(proto, key_id)
      expected = BSV.Crypto.sha256_hmac(inv, shared.point)
      assert secret == expected
    end
  end
end
