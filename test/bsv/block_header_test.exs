defmodule BSV.BlockHeaderTest do
  use ExUnit.Case, async: true
  alias BSV.BlockHeader

  # Bitcoin genesis block header (80 bytes hex)
  @genesis_header_hex "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

  # Genesis block hash (display order, reversed)
  @genesis_hash_hex "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

  describe "from_binary/1" do
    test "parses genesis block header" do
      bin = Base.decode16!(@genesis_header_hex, case: :lower)
      {:ok, header, rest} = BlockHeader.from_binary(bin)
      assert rest == <<>>
      assert header.version == 1
      assert header.nonce == 2_083_236_893
      assert header.bits == 0x1D00FFFF
      assert header.time == 1_231_006_505
    end

    test "returns error on short data" do
      assert {:error, _} = BlockHeader.from_binary(<<1, 2, 3>>)
    end

    test "preserves trailing data" do
      bin = Base.decode16!(@genesis_header_hex, case: :lower) <> <<0xFF>>
      {:ok, _header, rest} = BlockHeader.from_binary(bin)
      assert rest == <<0xFF>>
    end
  end

  describe "from_hex/1" do
    test "parses hex string" do
      {:ok, header} = BlockHeader.from_hex(@genesis_header_hex)
      assert header.version == 1
    end
  end

  describe "to_binary/1 and roundtrip" do
    test "roundtrips genesis header" do
      bin = Base.decode16!(@genesis_header_hex, case: :lower)
      {:ok, header, _} = BlockHeader.from_binary(bin)
      assert BlockHeader.to_binary(header) == bin
    end
  end

  describe "to_hex/1" do
    test "serializes to hex" do
      {:ok, header} = BlockHeader.from_hex(@genesis_header_hex)
      assert BlockHeader.to_hex(header) == @genesis_header_hex
    end
  end

  describe "hash/1 and hash_hex/1" do
    test "genesis block hash matches" do
      {:ok, header} = BlockHeader.from_hex(@genesis_header_hex)
      assert BlockHeader.hash_hex(header) == @genesis_hash_hex
    end

    test "hash returns 32-byte binary" do
      {:ok, header} = BlockHeader.from_hex(@genesis_header_hex)
      assert byte_size(BlockHeader.hash(header)) == 32
    end
  end

  describe "size/0" do
    test "always 80" do
      assert BlockHeader.size() == 80
    end
  end
end
