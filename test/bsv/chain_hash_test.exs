defmodule BSV.ChainHashTest do
  use ExUnit.Case, async: true

  @genesis_hex "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

  test "from_hex and to_hex roundtrip" do
    {:ok, hash} = BSV.ChainHash.from_hex(@genesis_hex)
    assert BSV.ChainHash.to_hex(hash) == @genesis_hex
  end

  test "from_bytes and to_bytes" do
    bytes = :crypto.strong_rand_bytes(32)
    hash = BSV.ChainHash.from_bytes(bytes)
    assert BSV.ChainHash.to_bytes(hash) == bytes
  end

  test "hex is byte-reversed" do
    {:ok, hash} = BSV.ChainHash.from_hex(@genesis_hex)
    raw = BSV.ChainHash.to_bytes(hash)
    # Last byte of raw should be first byte of hex
    assert :binary.at(raw, 31) == 0x00
  end

  test "String.Chars protocol" do
    {:ok, hash} = BSV.ChainHash.from_hex(@genesis_hex)
    assert to_string(hash) == @genesis_hex
  end

  test "from_hex! raises on invalid" do
    assert_raise ArgumentError, fn -> BSV.ChainHash.from_hex!("invalid") end
  end

  test "from_hex! success" do
    hash = BSV.ChainHash.from_hex!(@genesis_hex)
    assert BSV.ChainHash.to_hex(hash) == @genesis_hex
  end

  test "from_hex with wrong length" do
    assert {:error, "hex must be 64 characters"} = BSV.ChainHash.from_hex("aabb")
  end

  test "from_hex with invalid hex chars" do
    assert {:error, "invalid hex"} = BSV.ChainHash.from_hex(String.duplicate("ZZ", 32))
  end
end
