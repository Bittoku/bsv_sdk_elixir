defmodule BSV.Transaction.SighashTest do
  use ExUnit.Case, async: true

  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, Sighash}
  alias BSV.Script

  test "SIGHASH_ALL_FORKID preimage is deterministic" do
    # Build a simple 1-in 1-out tx
    {:ok, locking_script} = Script.from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")

    input = %Input{
      source_txid: <<1::256>>,
      source_tx_out_index: 0,
      source_output: %Output{satoshis: 100_000, locking_script: locking_script}
    }

    output = %Output{satoshis: 90_000, locking_script: locking_script}

    tx = %Transaction{
      version: 1,
      inputs: [input],
      outputs: [output],
      lock_time: 0
    }

    script_bin = Script.to_binary(locking_script)

    assert {:ok, preimage} = Sighash.calc_preimage(tx, 0, script_bin, 0x41, 100_000)
    assert is_binary(preimage)

    # Preimage should be deterministic
    assert {:ok, ^preimage} = Sighash.calc_preimage(tx, 0, script_bin, 0x41, 100_000)

    assert {:ok, hash} = Sighash.signature_hash(tx, 0, script_bin, 0x41, 100_000)
    assert byte_size(hash) == 32
  end

  test "input_index out of range" do
    tx = Transaction.new()
    assert {:error, :input_index_out_of_range} = Sighash.calc_preimage(tx, 0, <<>>, 0x41, 0)
  end

  test "bare SIGHASH_ALL (0x01) without FORKID returns error" do
    tx = Transaction.new()
    assert {:error, :missing_forkid} = Sighash.signature_hash(tx, 0, <<>>, 0x01, 0)
    assert {:error, :missing_forkid} = Sighash.calc_preimage(tx, 0, <<>>, 0x01, 0)
  end

  test "SIGHASH_ALL with FORKID (0x41) succeeds" do
    {:ok, locking_script} = Script.from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")

    input = %Input{
      source_txid: <<1::256>>,
      source_tx_out_index: 0,
      source_output: %Output{satoshis: 100_000, locking_script: locking_script}
    }

    output = %Output{satoshis: 90_000, locking_script: locking_script}

    tx = %Transaction{
      version: 1,
      inputs: [input],
      outputs: [output],
      lock_time: 0
    }

    script_bin = Script.to_binary(locking_script)
    assert {:ok, _hash} = Sighash.signature_hash(tx, 0, script_bin, 0x41, 100_000)
  end
end
