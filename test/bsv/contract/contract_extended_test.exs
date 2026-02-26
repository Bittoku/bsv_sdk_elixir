# Test contract modules (must be defined before test module)
defmodule BSV.Contract.P2PKHFull do
  use BSV.Contract

  @impl true
  def locking_script(ctx, %{pubkey_hash: pkh}) do
    ctx
    |> op_dup()
    |> op_hash160()
    |> push(pkh)
    |> op_equalverify()
    |> op_checksig()
  end

  @impl true
  def unlocking_script(ctx, %{privkey: privkey, pubkey: pubkey}) do
    ctx
    |> sig(privkey)
    |> push(pubkey)
  end
end

defmodule BSV.Contract.P2PKFull do
  use BSV.Contract

  @impl true
  def locking_script(ctx, %{pubkey: pubkey}) do
    ctx
    |> push(pubkey)
    |> op_checksig()
  end

  @impl true
  def unlocking_script(ctx, %{privkey: privkey}) do
    sig(ctx, privkey)
  end
end

defmodule BSV.Contract.ContractExtendedTest do
  use ExUnit.Case, async: true

  alias BSV.{Contract, PrivateKey, PublicKey}
  alias BSV.Contract.{P2PKH, P2PK, P2MS, OpReturn, Raw}
  alias BSV.Transaction.{Input, Output}

  describe "to_txout/1" do
    test "creates output from locking contract" do
      pkh = :crypto.strong_rand_bytes(20)
      contract = P2PKH.lock(5000, %{pubkey_hash: pkh})
      txout = Contract.to_txout(contract)

      assert %Output{} = txout
      assert txout.satoshis == 5000
      assert txout.locking_script.chunks != []
    end

    test "OpReturn output with 0 satoshis" do
      contract = OpReturn.lock(0, %{data: "hello"})
      txout = Contract.to_txout(contract)

      assert txout.satoshis == 0
      assert length(txout.locking_script.chunks) == 3
    end
  end

  describe "to_txin/1" do
    test "creates input from unlocking contract" do
      sig = :crypto.strong_rand_bytes(72)
      pubkey = :crypto.strong_rand_bytes(33)

      utxo = %{
        source_txid: :crypto.strong_rand_bytes(32),
        source_tx_out_index: 1,
        source_output: nil
      }

      contract = P2PKH.unlock(utxo, %{signature: sig, pubkey: pubkey})
      txin = Contract.to_txin(contract)

      assert %Input{} = txin
      assert txin.source_tx_out_index == 1
      assert txin.sequence_number == 0xFFFFFFFF
      assert txin.unlocking_script.chunks != []
    end

    test "custom sequence number via opts" do
      utxo = %{source_txid: <<0::256>>, source_tx_out_index: 0}

      contract = P2PKH.unlock(utxo, %{signature: <<1>>, pubkey: <<2>>}, sequence: 0)
      txin = Contract.to_txin(contract)

      assert txin.sequence_number == 0
    end
  end

  describe "simulate/3" do
    test "P2PKH lock/unlock roundtrip succeeds" do
      privkey = PrivateKey.generate()
      pubkey = PrivateKey.to_public_key(privkey)
      pubkey_bin = PublicKey.compress(pubkey).point
      pkh = :crypto.hash(:ripemd160, :crypto.hash(:sha256, pubkey_bin))

      # We need to build actual sig inside simulate, so we need a contract
      # that uses the sig helper. Let's test with our FullP2PKH module.
      # For now, test that simulate calls through without crash on a simple contract.

      # Actually, the existing P2PKH expects pre-computed signature and pubkey,
      # which doesn't work with simulate since we need the tx context.
      # Let's create a test contract that uses the sig helper.

      result = Contract.simulate(
        BSV.Contract.P2PKHFull,
        %{pubkey_hash: pkh},
        %{privkey: privkey, pubkey: pubkey_bin}
      )

      assert {:ok, true} = result
    end

    test "P2PKH simulate fails with wrong key" do
      privkey = PrivateKey.generate()
      wrong_privkey = PrivateKey.generate()
      pubkey = PrivateKey.to_public_key(wrong_privkey)
      pubkey_bin = PublicKey.compress(pubkey).point

      # Use correct PKH from the real key
      real_pubkey = PrivateKey.to_public_key(privkey)
      real_pubkey_bin = PublicKey.compress(real_pubkey).point
      pkh = :crypto.hash(:ripemd160, :crypto.hash(:sha256, real_pubkey_bin))

      result = Contract.simulate(
        BSV.Contract.P2PKHFull,
        %{pubkey_hash: pkh},
        %{privkey: wrong_privkey, pubkey: pubkey_bin}
      )

      assert {:error, _} = result
    end

    test "P2PK simulate succeeds" do
      privkey = PrivateKey.generate()
      pubkey = PrivateKey.to_public_key(privkey)
      pubkey_bin = PublicKey.compress(pubkey).point

      result = Contract.simulate(
        BSV.Contract.P2PKFull,
        %{pubkey: pubkey_bin},
        %{privkey: privkey}
      )

      assert {:ok, true} = result
    end
  end
end
