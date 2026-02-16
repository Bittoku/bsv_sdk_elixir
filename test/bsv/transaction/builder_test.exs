defmodule BSV.Transaction.BuilderTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey}
  alias BSV.Transaction
  alias BSV.Transaction.{Builder, P2PKH}

  test "pipe-friendly builder flow" do
    key = PrivateKey.generate()
    address = PrivateKey.to_public_key(key) |> PublicKey.to_address()
    {:ok, locking_script} = P2PKH.lock(address)
    locking_hex = BSV.Script.to_hex(locking_script)
    fake_txid = String.duplicate("aa", 32)

    tx =
      Builder.new()
      |> Builder.add_input(fake_txid, 0, locking_hex, 100_000)
      |> Builder.add_p2pkh_output(address, 90_000)
      |> Builder.add_op_return_output(["hello", "world"])

    assert length(tx.inputs) == 1
    assert length(tx.outputs) == 2

    # Sign
    assert {:ok, signed_tx} = Builder.sign_input(tx, 0, P2PKH.unlock(key))
    assert signed_tx.inputs |> hd() |> Map.get(:unlocking_script) != nil

    # Build (validate)
    assert {:ok, _} = Builder.build(signed_tx)

    # Serializes without error
    hex = Transaction.to_hex(signed_tx)
    assert is_binary(hex)
    assert {:ok, _} = Transaction.from_hex(hex)
  end

  test "sign_all_inputs" do
    key = PrivateKey.generate()
    address = PrivateKey.to_public_key(key) |> PublicKey.to_address()
    {:ok, locking_script} = P2PKH.lock(address)
    locking_hex = BSV.Script.to_hex(locking_script)
    fake_txid = String.duplicate("bb", 32)

    tx =
      Builder.new()
      |> Builder.add_input(fake_txid, 0, locking_hex, 50_000)
      |> Builder.add_input(fake_txid, 1, locking_hex, 50_000)
      |> Builder.add_p2pkh_output(address, 90_000)

    assert {:ok, signed} = Builder.sign_all_inputs(tx, P2PKH.unlock(key))
    assert Enum.all?(signed.inputs, &(&1.unlocking_script != nil))
  end

  test "build fails with no inputs" do
    tx = Builder.new() |> Builder.add_p2pkh_output("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1000)
    assert {:error, :no_inputs} = Builder.build(tx)
  end
end
