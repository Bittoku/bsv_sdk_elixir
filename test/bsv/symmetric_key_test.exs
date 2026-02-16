defmodule BSV.SymmetricKeyTest do
  use ExUnit.Case, async: true

  test "encrypt/decrypt roundtrip" do
    key = :crypto.strong_rand_bytes(32)
    plaintext = "Hello, BSV!"
    {:ok, encrypted} = BSV.SymmetricKey.encrypt(key, plaintext)
    {:ok, decrypted} = BSV.SymmetricKey.decrypt(key, encrypted)
    assert decrypted == plaintext
  end

  test "encrypt/decrypt empty plaintext" do
    key = :crypto.strong_rand_bytes(32)
    {:ok, encrypted} = BSV.SymmetricKey.encrypt(key, "")
    {:ok, decrypted} = BSV.SymmetricKey.decrypt(key, encrypted)
    assert decrypted == ""
  end

  test "wrong key fails" do
    key1 = :crypto.strong_rand_bytes(32)
    key2 = :crypto.strong_rand_bytes(32)
    {:ok, encrypted} = BSV.SymmetricKey.encrypt(key1, "secret")
    assert {:error, :decrypt_failed} = BSV.SymmetricKey.decrypt(key2, encrypted)
  end

  test "corrupted ciphertext fails" do
    key = :crypto.strong_rand_bytes(32)
    {:ok, encrypted} = BSV.SymmetricKey.encrypt(key, "secret")
    corrupted = binary_part(encrypted, 0, byte_size(encrypted) - 1) <> <<0xFF>>
    assert {:error, :decrypt_failed} = BSV.SymmetricKey.decrypt(key, corrupted)
  end

  test "too short input fails" do
    key = :crypto.strong_rand_bytes(32)
    assert {:error, :decrypt_failed} = BSV.SymmetricKey.decrypt(key, <<1, 2, 3>>)
  end
end
