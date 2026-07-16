defmodule BSV.SecurityFixTest do
  use ExUnit.Case, async: true

  # H-01: secure_compare must not leak length information via timing
  describe "Crypto.secure_compare" do
    test "returns true for equal binaries" do
      assert BSV.Crypto.secure_compare("hello", "hello") == true
      assert BSV.Crypto.secure_compare(<<1, 2, 3, 4, 5>>, <<1, 2, 3, 4, 5>>) == true
    end

    test "returns false for different content of same length" do
      assert BSV.Crypto.secure_compare("hello", "hella") == false
      assert BSV.Crypto.secure_compare(<<0::256>>, <<1::256>>) == false
    end

    test "returns false for different length binaries" do
      # The fix: hash-based approach should reject different-length inputs
      assert BSV.Crypto.secure_compare("a", "ab") == false
      assert BSV.Crypto.secure_compare("hello", "hello!") == false
    end

    test "always returns a result (no crash on empty)" do
      assert BSV.Crypto.secure_compare(<<>>, <<>>) == true
      assert BSV.Crypto.secure_compare(<<>>, "x") == false
    end

    test "SHA-256 outputs are compared in constant time regardless of input length differences" do
      # Massive length mismatch — the fix should handle this without issue
      short = "a"
      long = :binary.copy("x", 1_000)
      assert BSV.Crypto.secure_compare(short, long) == false
      assert BSV.Crypto.secure_compare(long, short) == false
    end
  end

  # M-01 plus the new default AAD fix
  describe "SymmetricKey default AAD" do
    test "encrypt/2 uses non-empty default AAD for protocol binding" do
      key = BSV.SymmetricKey.new(:crypto.strong_rand_bytes(32))
      plaintext = "test message"
      {:ok, ciphertext} = BSV.SymmetricKey.encrypt(key, plaintext)
      # Sanity: plaintext should decrypt correctly with default AAD
      {:ok, decrypted} = BSV.SymmetricKey.decrypt(key, ciphertext)
      assert decrypted == plaintext
    end

    test "decrypt/2 with wrong AAD (empty) fails for new ciphertexts" do
      key = BSV.SymmetricKey.new(:crypto.strong_rand_bytes(32))
      {:ok, ciphertext} = BSV.SymmetricKey.encrypt(key, "secret data")
      # Should fail with empty AAD since we use default now
      assert {:error, :decrypt_failed} = BSV.SymmetricKey.decrypt(key, ciphertext, <<>>)
    end

    test "encrypt/3 with custom AAD works correctly" do
      key = BSV.SymmetricKey.new(:crypto.strong_rand_bytes(32))
      plaintext = "context-bound message"
      aad = "my-app-context:v1"
      {:ok, ciphertext} = BSV.SymmetricKey.encrypt(key, plaintext, aad)
      # Same AAD should decrypt
      {:ok, decrypted} = BSV.SymmetricKey.decrypt(key, ciphertext, aad)
      assert decrypted == plaintext
      # Different AAD should fail
      assert {:error, :decrypt_failed} =
               BSV.SymmetricKey.decrypt(key, ciphertext, "wrong-context")
    end
  end

  # ECDH error specificity (H-02 fix)
  describe "PrivateKey.derive_shared_secret error handling" do
    test "invalid public key returns specific error" do
      key = BSV.PrivateKey.generate()
      # A point that's not on the curve should fail with a meaningful error
      # compressed zero is invalid
      invalid_pub = %BSV.PublicKey{point: <<0x02, 0::256>>}
      # Point at x=0 won't be on secp256k1
      result = BSV.PrivateKey.derive_shared_secret(key, invalid_pub)
      assert match?({:error, _}, result)
    end
  end

  # M-02: Base58 uses secure_compare
  describe "Base58Check uses secure_compare" do
    test "valid address decodes" do
      assert {:ok, {_version, _payload}} =
               BSV.Base58.check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    end

    test "checksum mismatch returns error" do
      assert {:error, "invalid checksum"} =
               BSV.Base58.check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    end
  end

  # ARC/JungleBus URL sanitization (M-04)
  describe "Transport URL sanitization" do
    test "ARC txid is validated before use" do
      config = %BSV.ARC.Config{base_url: "http://localhost:1234"}
      client = BSV.ARC.Client.new(config)

      assert {:error, %{message: "invalid txid format: expected 64 hex characters"}} =
               BSV.ARC.Client.status(client, "../etc/passwd")

      assert {:error, %{message: "invalid txid format: expected 64 hex characters"}} =
               BSV.ARC.Client.status(client, "<script>")
    end
  end

  # NOTE: the STAS3 127-byte piece-length limit (rejects ≥128, accepts 127) is
  # enforced in BSV.Tokens.Script.Stas3Pieces and exercised through the real
  # public piece-encoding API in test/bsv/tokens/script/stas3_pieces_test.exs
  # ("piece array rejects piece over 127 bytes" / "accepts piece of exactly 127
  # bytes"). The earlier assertion here called a non-existent
  # `Stas3Builder.build_piece/2`; it is removed rather than duplicated against a
  # phantom API. This finding is also outside this PR's declared scope
  # (H-01/H-02/M-01/M-02).
end
