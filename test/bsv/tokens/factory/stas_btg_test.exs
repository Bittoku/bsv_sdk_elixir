defmodule BSV.Tokens.Factory.StasBtgTest do
  use ExUnit.Case, async: true

  alias BSV.{Crypto, Script, Transaction, PrivateKey, PublicKey}
  alias BSV.Transaction.{Input, Output, P2PKH}
  alias BSV.Tokens.Factory.StasBtg, as: Factory
  alias BSV.Tokens.{Payment, Destination}

  defp test_payment(satoshis) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    addr = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, locking} = BSV.Script.Address.to_script(addr)

    %Payment{
      txid: :binary.copy(<<0xAA>>, 32),
      vout: 0,
      satoshis: satoshis,
      locking_script: locking,
      private_key: key
    }
  end

  defp test_btg_payment(satoshis) do
    payment = test_payment(satoshis)

    # Build a fake prev tx
    prev_tx = %Transaction{
      inputs: [
        %Input{
          source_txid: :binary.copy(<<0xDD>>, 32),
          source_tx_out_index: 0,
          unlocking_script: Script.new(),
          source_output: %Output{satoshis: satoshis, locking_script: payment.locking_script}
        }
      ],
      outputs: [%Output{satoshis: satoshis, locking_script: payment.locking_script}]
    }

    prev_raw = Transaction.to_binary(prev_tx)

    Map.put(payment, :prev_raw_tx, prev_raw)
  end

  defp test_destination(satoshis) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    addr = BSV.Base58.check_encode(pkh, 0x00)
    %Destination{address: addr, satoshis: satoshis}
  end

  defp rpkh, do: :binary.copy(<<0xBB>>, 20)

  # ---- Transfer ----

  test "btg_transfer_tx structure" do
    config = %{
      token_utxo: test_btg_payment(5000),
      destination: test_destination(5000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:ok, tx} = Factory.build_btg_transfer_tx(config)
    assert length(tx.inputs) == 2
    assert length(tx.outputs) >= 1
    assert Enum.at(tx.outputs, 0).satoshis == 5000
    assert tx.inputs |> Enum.at(0) |> Map.get(:unlocking_script) != nil
    assert tx.inputs |> Enum.at(1) |> Map.get(:unlocking_script) != nil
  end

  test "btg_transfer amount mismatch" do
    config = %{
      token_utxo: test_btg_payment(5000),
      destination: test_destination(3000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:error, _} = Factory.build_btg_transfer_tx(config)
  end

  # ---- Split ----

  test "btg_split_tx structure" do
    config = %{
      token_utxo: test_btg_payment(10000),
      destinations: [test_destination(4000), test_destination(6000)],
      redemption_pkh: rpkh(),
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:ok, tx} = Factory.build_btg_split_tx(config)
    assert Enum.at(tx.outputs, 0).satoshis == 4000
    assert Enum.at(tx.outputs, 1).satoshis == 6000
  end

  test "btg_split amount conservation" do
    config = %{
      token_utxo: test_btg_payment(10000),
      destinations: [test_destination(4000), test_destination(5000)],
      redemption_pkh: rpkh(),
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:error, _} = Factory.build_btg_split_tx(config)
  end

  test "btg_split no destinations" do
    config = %{
      token_utxo: test_btg_payment(10000),
      destinations: [],
      redemption_pkh: rpkh(),
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:error, _} = Factory.build_btg_split_tx(config)
  end

  test "btg_split too many destinations" do
    config = %{
      token_utxo: test_btg_payment(10000),
      destinations: Enum.map(1..5, fn _ -> test_destination(2000) end),
      redemption_pkh: rpkh(),
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:error, _} = Factory.build_btg_split_tx(config)
  end

  # ---- Merge ----

  test "btg_merge_tx structure" do
    config = %{
      token_utxos: [test_btg_payment(3000), test_btg_payment(7000)],
      destination: test_destination(10000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:ok, tx} = Factory.build_btg_merge_tx(config)
    assert length(tx.inputs) == 3
    assert Enum.at(tx.outputs, 0).satoshis == 10000
  end

  test "btg_merge amount mismatch" do
    config = %{
      token_utxos: [test_btg_payment(3000), test_btg_payment(7000)],
      destination: test_destination(9000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:error, _} = Factory.build_btg_merge_tx(config)
  end

  test "btg_merge single utxo rejected" do
    config = %{
      token_utxos: [test_btg_payment(3000)],
      destination: test_destination(3000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:error, _} = Factory.build_btg_merge_tx(config)
  end

  # ---- Checkpoint ----

  test "btg_checkpoint_tx structure" do
    issuer_key = PrivateKey.generate()

    config = %{
      token_utxo: test_payment(5000),
      issuer_private_key: issuer_key,
      destination: test_destination(5000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:ok, tx} = Factory.build_btg_checkpoint_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.at(tx.outputs, 0).satoshis == 5000

    # Token input should end with OP_FALSE (checkpoint path)
    unlock_bytes = Script.to_binary(Enum.at(tx.inputs, 0).unlocking_script)
    assert :binary.last(unlock_bytes) == 0x00
  end

  test "btg_checkpoint amount mismatch" do
    config = %{
      token_utxo: test_payment(5000),
      issuer_private_key: PrivateKey.generate(),
      destination: test_destination(3000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:error, _} = Factory.build_btg_checkpoint_tx(config)
  end

  test "btg_checkpoint output is STAS-BTG script" do
    config = %{
      token_utxo: test_payment(5000),
      issuer_private_key: PrivateKey.generate(),
      destination: test_destination(5000),
      redemption_pkh: rpkh(),
      splittable: true,
      funding: test_payment(50000),
      fee_rate: 500
    }

    assert {:ok, tx} = Factory.build_btg_checkpoint_tx(config)
    output_bytes = Script.to_binary(Enum.at(tx.outputs, 0).locking_script)
    assert :binary.first(output_bytes) == 0x63
  end
end
