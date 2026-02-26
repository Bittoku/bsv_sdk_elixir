defmodule BSV.Contract.SigHelperTest do
  use ExUnit.Case, async: true

  alias BSV.{Contract, PrivateKey, PublicKey, Script}
  alias BSV.Contract.P2PKH
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, Sighash}

  describe "sig/2 helper" do
    test "pushes placeholder when no tx context" do
      privkey = PrivateKey.generate()
      contract = P2PKH.unlock(%{}, %{signature: <<>>, pubkey: <<>>})

      # Manually test sig helper
      ctx = %Contract{mfa: {__MODULE__, :sig_test, [privkey]}, subject: %{}}
      script = Contract.to_script(ctx)
      # Should have a 71-byte zero placeholder
      [{:data, placeholder}] = script.chunks
      assert byte_size(placeholder) == 71
      assert placeholder == <<0::568>>
    end

    test "produces valid signature with tx context" do
      privkey = PrivateKey.generate()
      pubkey = PrivateKey.to_public_key(privkey)
      pubkey_bin = PublicKey.compress(pubkey).point

      pkh = :crypto.hash(:ripemd160, :crypto.hash(:sha256, pubkey_bin))

      # Create locking script
      lock_contract = P2PKH.lock(1000, %{pubkey_hash: pkh})
      locking_script = Contract.to_script(lock_contract)

      # Fake funding txid
      funding_txid = BSV.Crypto.sha256d("funding_tx")

      source_output = %Output{satoshis: 1000, locking_script: locking_script}

      # Build spending tx
      spending_tx = %Transaction{
        version: 1,
        inputs: [
          %Input{
            source_txid: funding_txid,
            source_tx_out_index: 0,
            unlocking_script: %Script{},
            sequence_number: 0xFFFFFFFF,
            source_output: source_output
          }
        ],
        outputs: [%Output{satoshis: 1000, locking_script: %Script{}}],
        lock_time: 0
      }

      utxo = %{
        source_txid: funding_txid,
        source_tx_out_index: 0,
        source_output: source_output
      }

      # Build unlock contract with context
      unlock_contract =
        P2PKH.unlock(utxo, %{signature: <<>>, pubkey: pubkey_bin})
        |> Contract.put_ctx({spending_tx, 0})

      # Use sig helper directly
      ctx = %Contract{
        mfa: {__MODULE__, :sig_test, [privkey]},
        ctx: {spending_tx, 0},
        subject: utxo
      }

      script = Contract.to_script(ctx)
      [{:data, signature}] = script.chunks

      # Signature should be non-zero and DER-encoded with sighash flag
      assert byte_size(signature) > 10
      assert :binary.last(signature) == 0x41

      # Verify the signature
      sig_body = binary_part(signature, 0, byte_size(signature) - 1)
      locking_bin = Script.to_binary(locking_script)

      {:ok, hash} = Sighash.signature_hash(spending_tx, 0, locking_bin, 0x41, 1000)
      assert :crypto.verify(:ecdsa, :sha256, {:digest, hash}, sig_body, [pubkey_bin, :secp256k1])
    end
  end

  import BSV.Contract.Helpers

  def sig_test(ctx, privkey) do
    sig(ctx, privkey)
  end
end
