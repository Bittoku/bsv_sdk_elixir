defmodule BSV.Transaction.InputTest do
  use ExUnit.Case, async: true

  alias BSV.Transaction.Input
  alias BSV.Transaction.Output

  describe "new/0" do
    test "creates default input" do
      input = Input.new()
      assert input.source_txid == <<0::256>>
      assert input.source_tx_out_index == 0
      assert input.sequence_number == 0xFFFFFFFF
      assert input.unlocking_script == nil
      assert input.source_output == nil
    end
  end

  describe "to_binary/1 and from_binary/1 roundtrip" do
    test "default input" do
      input = Input.new()
      bin = Input.to_binary(input)
      assert {:ok, decoded, <<>>} = Input.from_binary(bin)
      assert decoded.source_txid == input.source_txid
      assert decoded.source_tx_out_index == input.source_tx_out_index
      assert decoded.sequence_number == input.sequence_number
    end

    test "input with script" do
      {:ok, script} = BSV.Script.from_asm("OP_1")
      input = %Input{
        source_txid: :crypto.strong_rand_bytes(32),
        source_tx_out_index: 1,
        sequence_number: 0xFFFFFFFE,
        unlocking_script: script
      }
      bin = Input.to_binary(input)
      assert {:ok, decoded, <<>>} = Input.from_binary(bin)
      assert decoded.source_txid == input.source_txid
      assert decoded.source_tx_out_index == 1
      assert decoded.sequence_number == 0xFFFFFFFE
    end
  end

  describe "to_binary_cleared/1" do
    test "outputs empty script" do
      {:ok, script} = BSV.Script.from_asm("OP_1 OP_2")
      input = %Input{
        source_txid: <<0::256>>,
        source_tx_out_index: 0,
        unlocking_script: script
      }
      cleared = Input.to_binary_cleared(input)
      # Should have varint 0 for script length (no script bytes)
      assert byte_size(cleared) == 32 + 4 + 1 + 4
    end
  end

  describe "from_binary/1 error cases" do
    test "insufficient data" do
      assert {:error, :insufficient_data} = Input.from_binary(<<1, 2, 3>>)
    end

    test "invalid input data" do
      # Valid txid+vout but truncated
      assert {:error, _} = Input.from_binary(<<0::256, 0::little-32, 0xFF>>)
    end
  end

  describe "source_satoshis/1" do
    test "returns nil when no source_output" do
      assert Input.source_satoshis(%Input{}) == nil
    end

    test "returns satoshis from source_output" do
      input = %Input{source_output: %Output{satoshis: 5000}}
      assert Input.source_satoshis(input) == 5000
    end
  end

  describe "source_locking_script/1" do
    test "returns nil when no source_output" do
      assert Input.source_locking_script(%Input{}) == nil
    end

    test "returns script from source_output" do
      {:ok, script} = BSV.Script.from_asm("OP_1")
      input = %Input{source_output: %Output{locking_script: script}}
      assert Input.source_locking_script(input) == script
    end
  end
end
