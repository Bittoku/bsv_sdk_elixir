defmodule BSV.SPV.BeefTest do
  use ExUnit.Case, async: true

  alias BSV.SPV.Beef

  @genesis_tx_hex "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

  defp build_v2_beef_hex(format_byte, tx_hex) do
    tx_bin = Base.decode16!(tx_hex, case: :mixed)
    version = 4_022_206_466
    beef_bin = <<version::little-32, 0, 1, format_byte>> <> tx_bin
    Base.encode16(beef_bin, case: :lower)
  end

  test "beef_v1 constant" do
    assert Beef.beef_v1() == 4_022_206_465
  end

  test "beef_v2 constant" do
    assert Beef.beef_v2() == 4_022_206_466
  end

  test "from_bytes with data too short" do
    assert {:error, "data too short"} = Beef.from_bytes(<<1, 2, 3>>)
  end

  test "from_bytes with invalid version" do
    assert {:error, _} = Beef.from_bytes(<<0, 0, 0, 0, 0>>)
  end

  test "from_hex with invalid hex" do
    assert {:error, "invalid hex"} = Beef.from_hex("not_hex!")
  end

  test "from_hex V2 with raw tx (format 0)" do
    hex = build_v2_beef_hex(0, @genesis_tx_hex)
    assert {:ok, beef} = Beef.from_hex(hex)
    assert beef.version == 4_022_206_466
    assert map_size(beef.transactions) == 1
    # The transaction should be raw_tx format
    [tx_entry] = Map.values(beef.transactions)
    assert tx_entry.data_format == :raw_tx
    assert tx_entry.transaction != nil
  end

  test "from_bytes V2 with txid only (format 2)" do
    version = 4_022_206_466
    txid = :crypto.strong_rand_bytes(32)
    beef_bin = <<version::little-32, 0, 1, 2>> <> txid
    assert {:ok, beef} = Beef.from_bytes(beef_bin)
    assert map_size(beef.transactions) == 1
    [tx_entry] = Map.values(beef.transactions)
    assert tx_entry.data_format == :txid_only
    assert tx_entry.known_txid == txid
  end

  test "from_bytes V2 with raw tx + bump (format 1)" do
    version = 4_022_206_466
    tx_bin = Base.decode16!(@genesis_tx_hex, case: :mixed)
    bump_index = 0
    beef_bin = <<version::little-32, 0, 1, 1, bump_index>> <> tx_bin
    assert {:ok, beef} = Beef.from_bytes(beef_bin)
    [tx_entry] = Map.values(beef.transactions)
    assert tx_entry.data_format == :raw_tx_and_bump
    assert tx_entry.bump_index == 0
  end

  test "from_bytes V2 with invalid format byte" do
    version = 4_022_206_466
    beef_bin = <<version::little-32, 0, 1, 5, 0>>
    assert {:error, _} = Beef.from_bytes(beef_bin)
  end

  test "from_bytes atomic BEEF prefix" do
    # Atomic BEEF has 0x01010101 prefix followed by 32-byte skip, then normal BEEF body
    atomic_prefix = <<0x01010101::little-32>>
    skip = :crypto.strong_rand_bytes(32)
    version = 4_022_206_466
    tx_bin = Base.decode16!(@genesis_tx_hex, case: :mixed)
    beef_body = <<version::little-32, 0, 1, 0>> <> tx_bin
    full = atomic_prefix <> skip <> beef_body
    assert {:ok, beef} = Beef.from_bytes(full)
    assert beef.version == 4_022_206_466
  end

  test "struct creation" do
    beef = %Beef{version: Beef.beef_v1()}
    assert beef.bumps == []
    assert beef.transactions == %{}
  end

  test "BeefTx struct" do
    bt = %Beef.BeefTx{data_format: :raw_tx}
    assert bt.bump_index == 0
    assert bt.known_txid == nil
    assert bt.transaction == nil
  end

  test "from_bytes V1 with raw tx (no bump flag)" do
    version = 4_022_206_465
    tx_bin = Base.decode16!(@genesis_tx_hex, case: :mixed)
    # V1: version + 0 bumps + 1 tx + tx_bytes + flag byte 0x00 (no bump)
    beef_bin = <<version::little-32, 0, 1>> <> tx_bin <> <<0x00>>
    assert {:ok, beef} = Beef.from_bytes(beef_bin)
    assert beef.version == 4_022_206_465
    assert map_size(beef.transactions) == 1
    [tx_entry] = Map.values(beef.transactions)
    assert tx_entry.data_format == :raw_tx
  end

  test "from_bytes V1 with raw tx and bump flag" do
    version = 4_022_206_465
    tx_bin = Base.decode16!(@genesis_tx_hex, case: :mixed)
    # V1: version + 0 bumps + 1 tx + tx_bytes + flag 0x01 + bump_index varint 0
    beef_bin = <<version::little-32, 0, 1>> <> tx_bin <> <<0x01, 0>>
    assert {:ok, beef} = Beef.from_bytes(beef_bin)
    [tx_entry] = Map.values(beef.transactions)
    assert tx_entry.data_format == :raw_tx_and_bump
    assert tx_entry.bump_index == 0
  end

  test "from_bytes V1 with tx at end (no trailing bytes)" do
    version = 4_022_206_465
    tx_bin = Base.decode16!(@genesis_tx_hex, case: :mixed)
    # V1: no trailing flag byte - tx ends at EOF
    beef_bin = <<version::little-32, 0, 1>> <> tx_bin
    assert {:ok, beef} = Beef.from_bytes(beef_bin)
    assert map_size(beef.transactions) == 1
  end
end
