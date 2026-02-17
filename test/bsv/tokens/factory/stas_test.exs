defmodule BSV.Tokens.Factory.StasTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Crypto}
  alias BSV.Tokens.Factory.Stas
  alias BSV.Tokens.{Payment, Destination}

  defp test_payment(satoshis) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    address = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, script} = BSV.Script.Address.to_script(address)

    %Payment{
      txid: :binary.copy(<<0xAA>>, 32),
      vout: 0,
      satoshis: satoshis,
      locking_script: script,
      private_key: key
    }
  end

  defp test_destination(satoshis) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    address = BSV.Base58.check_encode(pkh, 0x00)
    %Destination{address: address, satoshis: satoshis}
  end

  defp redemption_pkh, do: :binary.copy(<<0xBB>>, 20)

  # ---- Issue tests ----

  test "issue tx structure" do
    config = %{
      contract_utxo: test_payment(10_000),
      destinations: [test_destination(10_000)],
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    {:ok, tx} = Stas.build_issue_tx(config)
    assert length(tx.inputs) == 2
    assert length(tx.outputs) >= 1
    assert Enum.at(tx.outputs, 0).satoshis == 10_000
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "issue amount mismatch" do
    config = %{
      contract_utxo: test_payment(10_000),
      destinations: [test_destination(5_000)],
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_issue_tx(config)
  end

  test "issue no destinations" do
    config = %{
      contract_utxo: test_payment(10_000),
      destinations: [],
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_issue_tx(config)
  end

  test "issue multiple destinations" do
    config = %{
      contract_utxo: test_payment(10_000),
      destinations: [test_destination(3_000), test_destination(7_000)],
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    {:ok, tx} = Stas.build_issue_tx(config)
    assert Enum.at(tx.outputs, 0).satoshis == 3_000
    assert Enum.at(tx.outputs, 1).satoshis == 7_000
  end

  # ---- Transfer tests ----

  test "transfer tx structure" do
    config = %{
      token_utxo: test_payment(5_000),
      destination: test_destination(5_000),
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    {:ok, tx} = Stas.build_transfer_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.at(tx.outputs, 0).satoshis == 5_000
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "transfer amount mismatch" do
    config = %{
      token_utxo: test_payment(5_000),
      destination: test_destination(3_000),
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_transfer_tx(config)
  end

  # ---- Split tests ----

  test "split tx structure" do
    config = %{
      token_utxo: test_payment(10_000),
      destinations: [test_destination(4_000), test_destination(6_000)],
      redemption_pkh: redemption_pkh(),
      funding: test_payment(50_000),
      fee_rate: 500
    }

    {:ok, tx} = Stas.build_split_tx(config)
    assert Enum.at(tx.outputs, 0).satoshis == 4_000
    assert Enum.at(tx.outputs, 1).satoshis == 6_000
  end

  test "split amount conservation" do
    config = %{
      token_utxo: test_payment(10_000),
      destinations: [test_destination(4_000), test_destination(5_000)],
      redemption_pkh: redemption_pkh(),
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_split_tx(config)
  end

  test "split too many destinations" do
    config = %{
      token_utxo: test_payment(10_000),
      destinations: Enum.map(1..5, fn _ -> test_destination(2_000) end),
      redemption_pkh: redemption_pkh(),
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_split_tx(config)
  end

  test "split no destinations" do
    config = %{
      token_utxo: test_payment(10_000),
      destinations: [],
      redemption_pkh: redemption_pkh(),
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_split_tx(config)
  end

  # ---- Merge tests ----

  test "merge tx structure" do
    config = %{
      token_utxos: [test_payment(3_000), test_payment(7_000)],
      destination: test_destination(10_000),
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    {:ok, tx} = Stas.build_merge_tx(config)
    assert length(tx.inputs) == 3
    assert Enum.at(tx.outputs, 0).satoshis == 10_000
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "merge amount mismatch" do
    config = %{
      token_utxos: [test_payment(3_000), test_payment(7_000)],
      destination: test_destination(9_000),
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_merge_tx(config)
  end

  test "merge single utxo rejected" do
    config = %{
      token_utxos: [test_payment(3_000)],
      destination: test_destination(3_000),
      redemption_pkh: redemption_pkh(),
      splittable: true,
      funding: test_payment(50_000),
      fee_rate: 500
    }

    assert {:error, _} = Stas.build_merge_tx(config)
  end

  # ---- Redeem tests ----

  test "redeem tx structure" do
    config = %{
      token_utxo: test_payment(5_000),
      funding: test_payment(50_000),
      fee_rate: 500
    }

    {:ok, tx} = Stas.build_redeem_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.at(tx.outputs, 0).satoshis == 0
    assert BSV.Script.is_op_return?(Enum.at(tx.outputs, 0).locking_script)

    if length(tx.outputs) > 1 do
      assert Enum.at(tx.outputs, 1).satoshis > 0
    end

    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end
end
