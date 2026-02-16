defmodule BSV.Transaction.P2PKHTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Script}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2PKH, Sighash}

  test "lock creates P2PKH locking script from address" do
    key = PrivateKey.generate()
    address = PrivateKey.to_public_key(key) |> PublicKey.to_address()
    assert {:ok, script} = P2PKH.lock(address)
    assert Script.is_p2pkh?(script)
  end

  test "end-to-end sign and verify" do
    # Generate key and address
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key)
    address = PublicKey.to_address(pubkey)

    # Create locking script
    {:ok, locking_script} = P2PKH.lock(address)

    # Fake a funding txid
    funding_txid = :crypto.strong_rand_bytes(32)

    # Build spending tx
    input = %Input{
      source_txid: funding_txid,
      source_tx_out_index: 0,
      source_output: %Output{satoshis: 100_000, locking_script: locking_script}
    }

    {:ok, dest_script} = P2PKH.lock(address)

    tx = %Transaction{
      version: 1,
      inputs: [input],
      outputs: [%Output{satoshis: 90_000, locking_script: dest_script}],
      lock_time: 0
    }

    # Sign
    unlocker = P2PKH.unlock(key)
    assert {:ok, unlocking_script} = P2PKH.sign(unlocker, tx, 0)

    # Verify signature manually
    [{:data, sig_with_flag}, {:data, _pubkey_bytes}] = unlocking_script.chunks
    sig_len = byte_size(sig_with_flag) - 1
    <<der_sig::binary-size(sig_len), _flag::8>> = sig_with_flag

    locking_script_bin = Script.to_binary(locking_script)
    {:ok, sighash} = Sighash.signature_hash(tx, 0, locking_script_bin, 0x41, 100_000)

    assert PublicKey.verify(pubkey, sighash, der_sig)
  end

  test "sign fails without source_output" do
    key = PrivateKey.generate()
    input = %Input{source_txid: <<1::256>>, source_tx_out_index: 0}
    tx = %Transaction{inputs: [input], outputs: [Output.new()]}
    unlocker = P2PKH.unlock(key)
    assert {:error, :missing_source_output} = P2PKH.sign(unlocker, tx, 0)
  end
end
