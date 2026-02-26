defmodule BSV.BlockTest do
  use ExUnit.Case, async: true
  alias BSV.{Block, BlockHeader}

  # Bitcoin genesis block (full, hex)
  # Header (80 bytes) + varint(1) + coinbase tx
  @genesis_block_hex "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

  @genesis_hash_hex "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

  describe "from_binary/1" do
    test "parses genesis block" do
      bin = Base.decode16!(@genesis_block_hex, case: :mixed)
      {:ok, block, rest} = Block.from_binary(bin)
      assert rest == <<>>
      assert block.header.version == 1
      assert length(block.txns) == 1
    end

    test "preserves trailing data" do
      bin = Base.decode16!(@genesis_block_hex, case: :mixed) <> <<0xAB>>
      {:ok, _block, rest} = Block.from_binary(bin)
      assert rest == <<0xAB>>
    end
  end

  describe "from_hex/1" do
    test "parses genesis block from hex" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      assert length(block.txns) == 1
    end
  end

  describe "to_binary/1 roundtrip" do
    test "roundtrips genesis block" do
      bin = Base.decode16!(@genesis_block_hex, case: :mixed)
      {:ok, block, _} = Block.from_binary(bin)
      assert Block.to_binary(block) == bin
    end
  end

  describe "to_hex/1" do
    test "serializes to hex" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      assert Block.to_hex(block) == @genesis_block_hex
    end
  end

  describe "hash/1 and hash_hex/1" do
    test "genesis block hash" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      assert Block.hash_hex(block) == @genesis_hash_hex
    end
  end

  describe "calc_merkle_root/1" do
    test "genesis block merkle root matches header" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      assert Block.valid_merkle_root?(block)
    end

    test "single tx merkle root equals txid" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      [tx] = block.txns
      txid = BSV.Transaction.tx_id(tx)
      assert Block.calc_merkle_root(block) == txid
    end
  end

  describe "tx_count/1" do
    test "genesis has 1 transaction" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      assert Block.tx_count(block) == 1
    end
  end

  describe "genesis?/1" do
    test "genesis block is genesis" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      assert Block.genesis?(block)
    end

    test "non-genesis block is not genesis" do
      {:ok, block} = Block.from_hex(@genesis_block_hex)
      non_genesis = %{block | header: %{block.header | prev_hash: <<1::256>>}}
      refute Block.genesis?(non_genesis)
    end
  end
end
