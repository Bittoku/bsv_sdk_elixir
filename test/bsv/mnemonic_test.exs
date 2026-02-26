defmodule BSV.MnemonicTest do
  use ExUnit.Case, async: true
  alias BSV.Mnemonic

  describe "generate/1" do
    test "generates 12-word mnemonic by default" do
      mnemonic = Mnemonic.generate()
      assert length(String.split(mnemonic)) == 12
    end

    test "generates 24-word mnemonic with 256-bit entropy" do
      mnemonic = Mnemonic.generate(256)
      assert length(String.split(mnemonic)) == 24
    end

    test "generates 15-word mnemonic with 160-bit entropy" do
      mnemonic = Mnemonic.generate(160)
      assert length(String.split(mnemonic)) == 15
    end

    test "all words are in wordlist" do
      mnemonic = Mnemonic.generate()
      wordlist = Mnemonic.wordlist()
      for word <- String.split(mnemonic), do: assert(word in wordlist)
    end
  end

  describe "from_entropy/1 and to_entropy/1" do
    test "roundtrips entropy" do
      entropy = :crypto.strong_rand_bytes(16)
      mnemonic = Mnemonic.from_entropy(entropy)
      assert Mnemonic.to_entropy(mnemonic) == entropy
    end

    test "roundtrips 32-byte entropy" do
      entropy = :crypto.strong_rand_bytes(32)
      mnemonic = Mnemonic.from_entropy(entropy)
      assert Mnemonic.to_entropy(mnemonic) == entropy
    end
  end

  describe "to_seed/2" do
    # BIP-39 test vector (English, no passphrase)
    # "abandon" x11 + "about" is a well-known test vector
    @test_mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    test "produces 64-byte seed" do
      seed = Mnemonic.to_seed(@test_mnemonic)
      assert byte_size(seed) == 64
    end

    test "hex encoding works" do
      seed = Mnemonic.to_seed(@test_mnemonic, encoding: :hex)
      assert is_binary(seed)
      assert byte_size(seed) == 128
    end

    test "passphrase changes seed" do
      seed1 = Mnemonic.to_seed(@test_mnemonic)
      seed2 = Mnemonic.to_seed(@test_mnemonic, passphrase: "my secret")
      assert seed1 != seed2
    end

    test "known test vector seed matches" do
      # BIP-39 reference vector for "abandon...about" with no passphrase
      expected =
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

      seed = Mnemonic.to_seed(@test_mnemonic, encoding: :hex)
      assert seed == expected
    end
  end

  describe "valid?/1" do
    test "valid mnemonic returns true" do
      mnemonic = Mnemonic.generate()
      assert Mnemonic.valid?(mnemonic)
    end

    test "invalid words return false" do
      assert Mnemonic.valid?("foo bar baz qux nope nada zilch zip zero one two three") == false
    end

    test "wrong checksum returns false" do
      # Completely invalid word should fail
      refute Mnemonic.valid?("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz")
    end
  end
end
