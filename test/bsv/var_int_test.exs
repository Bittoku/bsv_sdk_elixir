defmodule BSV.VarIntTest do
  use ExUnit.Case, async: true

  test "encode/decode < 0xFD" do
    assert BSV.VarInt.encode(0) == <<0>>
    assert BSV.VarInt.encode(252) == <<252>>
    assert {:ok, {252, <<>>}} = BSV.VarInt.decode(<<252>>)
  end

  test "encode/decode 0xFD range" do
    assert BSV.VarInt.encode(253) == <<0xFD, 253, 0>>
    assert BSV.VarInt.encode(0xFFFF) == <<0xFD, 0xFF, 0xFF>>
    assert {:ok, {253, <<>>}} = BSV.VarInt.decode(<<0xFD, 253, 0>>)
  end

  test "encode/decode 0xFE range" do
    assert BSV.VarInt.encode(0x10000) == <<0xFE, 0, 0, 1, 0>>
    assert {:ok, {0x10000, <<>>}} = BSV.VarInt.decode(<<0xFE, 0, 0, 1, 0>>)
  end

  test "encode/decode 0xFF range" do
    val = 0x100000000
    encoded = BSV.VarInt.encode(val)
    assert <<0xFF, _::binary>> = encoded
    assert {:ok, {^val, <<>>}} = BSV.VarInt.decode(encoded)
  end

  test "decode with remaining bytes" do
    assert {:ok, {1, <<2, 3>>}} = BSV.VarInt.decode(<<1, 2, 3>>)
  end

  test "decode empty" do
    assert {:error, _} = BSV.VarInt.decode(<<>>)
  end
end
