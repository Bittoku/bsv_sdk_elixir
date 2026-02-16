defmodule BSV.PublicKeyTest do
  use ExUnit.Case, async: true

  test "from_private_key returns compressed key" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PublicKey.from_private_key(key)
    assert byte_size(pub.point) == 33
    assert :binary.first(pub.point) in [0x02, 0x03]
  end

  test "compress idempotent" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PublicKey.from_private_key(key)
    assert BSV.PublicKey.compress(pub).point == pub.point
  end

  test "decompress and recompress roundtrip" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PublicKey.from_private_key(key)
    {:ok, uncompressed} = BSV.PublicKey.decompress(pub)
    assert byte_size(uncompressed.point) == 65
    recompressed = BSV.PublicKey.compress(uncompressed)
    assert recompressed.point == pub.point
  end

  test "to_address produces valid base58check" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PublicKey.from_private_key(key)
    addr = BSV.PublicKey.to_address(pub)
    assert String.starts_with?(addr, "1")
    assert {:ok, {0x00, _}} = BSV.Base58.check_decode(addr)
  end

  test "testnet address" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PublicKey.from_private_key(key)
    addr = BSV.PublicKey.to_address(pub, network: :testnet)
    assert {:ok, {0x6F, _}} = BSV.Base58.check_decode(addr)
  end

  test "from_bytes valid compressed" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PublicKey.from_private_key(key)
    assert {:ok, _} = BSV.PublicKey.from_bytes(pub.point)
  end

  test "from_bytes invalid" do
    assert {:error, _} = BSV.PublicKey.from_bytes(<<0x05, 0::256>>)
  end

  test "verify with wrong message fails" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PrivateKey.to_public_key(key)
    msg = BSV.Crypto.sha256("test")
    {:ok, sig} = BSV.PrivateKey.sign(key, msg)
    wrong_msg = BSV.Crypto.sha256("wrong")
    refute BSV.PublicKey.verify(pub, wrong_msg, sig)
  end
end
