defmodule BSV.CryptoTest do
  use ExUnit.Case, async: true

  test "sha256 of empty string" do
    expected = Base.decode16!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    assert BSV.Crypto.sha256("") == expected
  end

  test "sha256d of empty string" do
    first = BSV.Crypto.sha256("")
    expected = BSV.Crypto.sha256(first)
    assert BSV.Crypto.sha256d("") == expected
  end

  test "ripemd160 of empty string" do
    expected = Base.decode16!("9C1185A5C5E9FC54612808977EE8F548B2258D31")
    assert BSV.Crypto.ripemd160("") == expected
  end

  test "hash160" do
    data = "hello"
    expected = BSV.Crypto.ripemd160(BSV.Crypto.sha256(data))
    assert BSV.Crypto.hash160(data) == expected
  end

  test "sha512 produces 64 bytes" do
    assert byte_size(BSV.Crypto.sha512("test")) == 64
  end

  test "sha256_hmac" do
    result = BSV.Crypto.sha256_hmac("data", "key")
    assert byte_size(result) == 32
  end
end
