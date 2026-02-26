defmodule BSV.ExtKeyTest do
  use ExUnit.Case, async: true
  alias BSV.{ExtKey, Mnemonic, PublicKey}

  # BIP-32 test vector 1
  # Seed: 000102030405060708090a0b0c0d0e0f
  @seed1 Base.decode16!("000102030405060708090A0B0C0D0E0F")

  describe "from_seed/2" do
    test "creates master key from seed" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      assert master.depth == 0
      assert master.fingerprint == <<0, 0, 0, 0>>
      assert master.child_index == 0
      assert master.privkey != nil
      assert master.pubkey != nil
    end

    test "known BIP-32 test vector 1 master key" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      xprv = ExtKey.to_string(master)
      assert xprv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

      xpub = ExtKey.to_public(master) |> ExtKey.to_string()
      assert xpub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    end

    test "rejects too-short seed" do
      assert {:error, _} = ExtKey.from_seed(<<1, 2, 3>>)
    end
  end

  describe "from_seed!/2" do
    test "raises on invalid seed" do
      assert_raise ArgumentError, fn ->
        ExtKey.from_seed!(<<1, 2, 3>>)
      end
    end
  end

  describe "derive/2" do
    test "BIP-32 vector 1: m/0'" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      child = ExtKey.derive(master, "m/0'")
      assert child.depth == 1

      xprv = ExtKey.to_string(child)
      assert xprv == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    end

    test "BIP-32 vector 1: m/0'/1" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      child = ExtKey.derive(master, "m/0'/1")
      assert child.depth == 2

      xprv = ExtKey.to_string(child)
      assert xprv == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    end

    test "BIP-32 vector 1: m/0'/1/2'" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      child = ExtKey.derive(master, "m/0'/1/2'")
      assert child.depth == 3

      xpub = ExtKey.to_public(child) |> ExtKey.to_string()
      assert xpub == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
    end

    test "deep derivation path" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      child = ExtKey.derive(master, "m/0'/1/2'/2/1000000000")
      assert child.depth == 5

      xprv = ExtKey.to_string(child)
      assert xprv == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    end

    test "public derivation from xpub" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      priv_child = ExtKey.derive(master, "m/0'/0")
      pub_only = ExtKey.to_public(ExtKey.derive(master, "m/0'"))
      pub_child = ExtKey.derive(pub_only, "M/0")

      # Public keys should match
      assert pub_child.pubkey.point == priv_child.pubkey.point
    end

    test "cannot derive hardened from public parent" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      pub = ExtKey.to_public(master)

      assert_raise ArgumentError, ~r/hardened/, fn ->
        ExtKey.derive(pub, "M/0'")
      end
    end

    test "cannot derive private from public parent" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      pub = ExtKey.to_public(master)

      assert_raise ArgumentError, ~r/private child from public parent/, fn ->
        ExtKey.derive(pub, "m/0")
      end
    end

    test "invalid path raises" do
      {:ok, master} = ExtKey.from_seed(@seed1)

      assert_raise ArgumentError, fn ->
        ExtKey.derive(master, "invalid")
      end
    end
  end

  describe "from_string/1 and to_string/1" do
    test "roundtrip xprv" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      xprv = ExtKey.to_string(master)
      {:ok, decoded} = ExtKey.from_string(xprv)
      assert ExtKey.to_string(decoded) == xprv
    end

    test "roundtrip xpub" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      pub = ExtKey.to_public(master)
      xpub = ExtKey.to_string(pub)
      {:ok, decoded} = ExtKey.from_string(xpub)
      assert ExtKey.to_string(decoded) == xpub
    end

    test "from_string! raises on invalid" do
      assert_raise ArgumentError, fn ->
        ExtKey.from_string!("xprvinvalid")
      end
    end
  end

  describe "integration with Mnemonic" do
    test "mnemonic → seed → master key → derive" do
      mnemonic = Mnemonic.generate()
      seed = Mnemonic.to_seed(mnemonic)
      {:ok, master} = ExtKey.from_seed(seed)
      child = ExtKey.derive(master, "m/44'/0'/0'/0/0")
      assert child.depth == 5
      assert child.pubkey != nil
    end
  end

  describe "to_public/1" do
    test "strips private key" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      pub = ExtKey.to_public(master)
      assert pub.privkey == nil
      assert pub.pubkey == master.pubkey
    end

    test "idempotent on public key" do
      {:ok, master} = ExtKey.from_seed(@seed1)
      pub = ExtKey.to_public(master)
      assert ExtKey.to_public(pub) == pub
    end
  end
end
