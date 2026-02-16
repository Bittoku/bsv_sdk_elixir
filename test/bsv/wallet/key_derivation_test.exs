defmodule BSV.Wallet.KeyDerivationTest do
  @moduledoc "Tests for PrivateKey/PublicKey derive_child and derive_shared_secret."
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey}

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  describe "derive_shared_secret" do
    test "ECDH shared secret is deterministic" do
      a = make_key(42)
      b = make_key(69)
      b_pub = PrivateKey.to_public_key(b)
      a_pub = PrivateKey.to_public_key(a)

      {:ok, s1} = PrivateKey.derive_shared_secret(a, b_pub)
      {:ok, s2} = PrivateKey.derive_shared_secret(b, a_pub)
      assert s1.point == s2.point
    end

    test "PublicKey.derive_shared_secret delegates correctly" do
      a = make_key(42)
      b_pub = PrivateKey.to_public_key(make_key(69))

      {:ok, s1} = PrivateKey.derive_shared_secret(a, b_pub)
      {:ok, s2} = PublicKey.derive_shared_secret(b_pub, a)
      assert s1.point == s2.point
    end
  end

  describe "derive_child" do
    test "PrivateKey.derive_child produces valid key" do
      root = make_key(42)
      cp_pub = PrivateKey.to_public_key(make_key(69))
      assert {:ok, %PrivateKey{}} = PrivateKey.derive_child(root, cp_pub, "0-testprotocol-key1")
    end

    test "different invoice numbers produce different keys" do
      root = make_key(42)
      cp_pub = PrivateKey.to_public_key(make_key(69))
      {:ok, k1} = PrivateKey.derive_child(root, cp_pub, "0-testprotocol-key1")
      {:ok, k2} = PrivateKey.derive_child(root, cp_pub, "0-testprotocol-key2")
      assert k1.raw != k2.raw
    end

    test "PublicKey.derive_child produces counterparty's derived key" do
      root = make_key(42)
      cp = make_key(69)
      cp_pub = PrivateKey.to_public_key(cp)
      root_pub = PrivateKey.to_public_key(root)

      # Counterparty derives their child private key using root's pub key
      {:ok, cp_priv_child} = PrivateKey.derive_child(cp, root_pub, "0-testprotocol-key1")
      cp_pub_from_priv = PrivateKey.to_public_key(cp_priv_child)

      # Root derives counterparty's child public key without counterparty's private key
      {:ok, pub_child} = PublicKey.derive_child(cp_pub, root, "0-testprotocol-key1")

      assert cp_pub_from_priv.point == pub_child.point
    end
  end
end
