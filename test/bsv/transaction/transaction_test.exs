defmodule BSV.Transaction.TransactionTest do
  use ExUnit.Case, async: true

  alias BSV.Transaction
  alias BSV.Transaction

  @genesis_coinbase_hex "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
  @genesis_txid "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

  test "new/0 returns default transaction" do
    tx = Transaction.new()
    assert tx.version == 1
    assert tx.inputs == []
    assert tx.outputs == []
    assert tx.lock_time == 0
  end

  test "from_hex and tx_id_hex with genesis coinbase" do
    assert {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    assert tx.version == 1
    assert length(tx.inputs) == 1
    assert length(tx.outputs) == 1
    assert tx.lock_time == 0
    assert Transaction.tx_id_hex(tx) == @genesis_txid
  end

  test "is_coinbase? with genesis coinbase" do
    {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    assert Transaction.is_coinbase?(tx)
  end

  test "is_coinbase? with non-coinbase" do
    tx = Transaction.new()
    refute Transaction.is_coinbase?(tx)
  end

  test "serialize/deserialize roundtrip" do
    {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    bin = Transaction.to_binary(tx)
    assert {:ok, tx2, <<>>} = Transaction.from_binary(bin)
    assert Transaction.to_hex(tx2) == @genesis_coinbase_hex
  end

  test "total_output_satoshis" do
    {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    assert Transaction.total_output_satoshis(tx) == 5_000_000_000
  end

  test "add_input_from and total_input_satoshis" do
    {:ok, script} = BSV.Script.from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")

    {:ok, tx} =
      Transaction.add_input_from(
        Transaction.new(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0,
        BSV.Script.to_hex(script),
        50000
      )

    assert length(tx.inputs) == 1
    assert {:ok, 50000} = Transaction.total_input_satoshis(tx)
  end

  test "size returns byte length" do
    {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    assert Transaction.size(tx) == byte_size(Base.decode16!(@genesis_coinbase_hex, case: :mixed))
  end

  test "from_binary with insufficient data" do
    assert {:error, :insufficient_data} = Transaction.from_binary(<<1, 2, 3>>)
  end

  test "from_hex with invalid hex" do
    assert {:error, :invalid_hex} = Transaction.from_hex("not_hex!")
  end

  test "from_binary with extra data" do
    {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    bin = Transaction.to_binary(tx) <> <<0xFF>>
    assert {:ok, _tx2, <<0xFF>>} = Transaction.from_binary(bin)
  end

  test "total_input_satoshis with missing source_output" do
    tx = %Transaction{inputs: [BSV.Transaction.Input.new()]}
    assert {:error, :missing_source_output} = Transaction.total_input_satoshis(tx)
  end

  test "add_output" do
    tx = Transaction.new()
    output = BSV.Transaction.Output.new()
    tx2 = Transaction.add_output(tx, output)
    assert length(tx2.outputs) == 1
  end

  test "add_input" do
    tx = Transaction.new()
    input = BSV.Transaction.Input.new()
    tx2 = Transaction.add_input(tx, input)
    assert length(tx2.inputs) == 1
  end

  test "add_input_from with invalid txid hex" do
    assert {:error, :invalid_txid_hex} = Transaction.add_input_from(Transaction.new(), "short", 0, "76a91400000000000000000000000000000000000000008ac", 1000)
  end

  test "txid_binary returns 32 bytes" do
    {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    assert byte_size(Transaction.txid_binary(tx)) == 32
  end

  test "calc_input_signature_hash with missing source_output" do
    tx = %Transaction{inputs: [BSV.Transaction.Input.new()]}
    assert {:error, :missing_source_output} = Transaction.calc_input_signature_hash(tx, 0, 0x41)
  end

  test "to_hex roundtrip" do
    {:ok, tx} = Transaction.from_hex(@genesis_coinbase_hex)
    assert Transaction.to_hex(tx) == @genesis_coinbase_hex
  end
end
