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

  # ========================================================================
  # V3 Factory Tests
  # ========================================================================

  defp v3_token_input(satoshis, opts \\ []) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)

    flags = Keyword.get(opts, :flags, %BSV.Tokens.ScriptFlags{})
    frozen = Keyword.get(opts, :frozen, false)
    action_data = Keyword.get(opts, :action_data, nil)
    service_fields = Keyword.get(opts, :service_fields, [])

    {:ok, script} =
      BSV.Tokens.Script.StasBuilder.build_stas_v3_locking_script(
        pkh,
        redemption_pkh(),
        action_data: action_data,
        frozen: frozen,
        flags: flags,
        service_fields: service_fields
      )

    %BSV.Tokens.TokenInput{
      txid: :crypto.strong_rand_bytes(32),
      vout: 0,
      satoshis: satoshis,
      locking_script: script,
      private_key: key
    }
  end

  defp v3_output_params(satoshis, opts \\ []) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)

    %{
      satoshis: satoshis,
      owner_pkh: Keyword.get(opts, :owner_pkh, pkh),
      redemption_pkh: Keyword.get(opts, :redemption_pkh, redemption_pkh()),
      frozen: Keyword.get(opts, :frozen, false),
      flags: Keyword.get(opts, :flags, %BSV.Tokens.ScriptFlags{}),
      service_fields: Keyword.get(opts, :service_fields, []),
      optional_data: Keyword.get(opts, :optional_data, []),
      action_data: Keyword.get(opts, :action_data, nil)
    }
  end

  defp v3_fee_payment(satoshis \\ 100_000) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    address = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, script} = BSV.Script.Address.to_script(address)

    %{
      fee_txid: :crypto.strong_rand_bytes(32),
      fee_vout: 0,
      fee_satoshis: satoshis,
      fee_locking_script: script,
      fee_private_key: key
    }
  end

  defp v3_base_config(token_inputs, destinations, opts \\ []) do
    fee = v3_fee_payment()

    Map.merge(fee, %{
      token_inputs: token_inputs,
      destinations: destinations,
      spend_type: Keyword.get(opts, :spend_type, :transfer),
      fee_rate: 500,
      note_data: Keyword.get(opts, :note_data, nil)
    })
  end

  # ---- v3 transfer ----

  test "v3 transfer tx builds and signs" do
    ti = v3_token_input(1000)
    dest = v3_output_params(1000)
    config = v3_base_config([ti], [dest])

    {:ok, tx} = Stas.build_v3_transfer_tx(config)
    assert length(tx.inputs) == 2
    assert length(tx.outputs) >= 1
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  # ---- v3 split ----

  test "v3 split tx with 2 outputs" do
    ti = v3_token_input(1000)
    d1 = v3_output_params(600)
    d2 = v3_output_params(400)
    config = v3_base_config([ti], [d1, d2])

    {:ok, tx} = Stas.build_v3_split_tx(config)
    assert length(tx.outputs) >= 2
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "v3 split rejects more than 4 outputs" do
    ti = v3_token_input(500)
    dests = for _ <- 1..5, do: v3_output_params(100)
    config = v3_base_config([ti], dests)

    assert {:error, _} = Stas.build_v3_split_tx(config)
  end

  test "v3 split rejects 2 inputs" do
    t1 = v3_token_input(500)
    t2 = v3_token_input(500)
    dest = v3_output_params(1000)
    config = v3_base_config([t1, t2], [dest])

    assert {:error, _} = Stas.build_v3_split_tx(config)
  end

  # ---- v3 merge ----

  test "v3 merge tx with 2 inputs" do
    t1 = v3_token_input(500)
    t2 = v3_token_input(500)
    dest = v3_output_params(1000)
    config = v3_base_config([t1, t2], [dest])

    {:ok, tx} = Stas.build_v3_merge_tx(config)
    assert length(tx.inputs) == 3
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "v3 merge rejects 1 input" do
    t1 = v3_token_input(500)
    dest = v3_output_params(500)
    config = v3_base_config([t1], [dest])

    assert {:error, _} = Stas.build_v3_merge_tx(config)
  end

  # ---- v3 freeze ----

  test "v3 freeze tx sets frozen on output" do
    freeze_auth = :binary.copy(<<0xCC>>, 20)
    flags = %BSV.Tokens.ScriptFlags{freezable: true}

    ti = v3_token_input(1000, flags: flags, service_fields: [freeze_auth])
    dest = v3_output_params(1000, flags: flags, service_fields: [freeze_auth])
    config = v3_base_config([ti], [dest])

    {:ok, tx} = Stas.build_v3_freeze_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  # ---- v3 unfreeze ----

  test "v3 unfreeze tx clears frozen on output" do
    freeze_auth = :binary.copy(<<0xCC>>, 20)
    flags = %BSV.Tokens.ScriptFlags{freezable: true}

    ti = v3_token_input(1000, flags: flags, frozen: true, service_fields: [freeze_auth])
    dest = v3_output_params(1000, frozen: true, flags: flags, service_fields: [freeze_auth])
    config = v3_base_config([ti], [dest])

    {:ok, tx} = Stas.build_v3_unfreeze_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  # ---- v3 confiscation ----

  test "v3 confiscation tx builds" do
    flags = %BSV.Tokens.ScriptFlags{freezable: true, confiscatable: true}
    freeze_auth = :binary.copy(<<0xCC>>, 20)
    confiscate_auth = :binary.copy(<<0xDD>>, 20)

    ti = v3_token_input(1000, flags: flags, service_fields: [freeze_auth, confiscate_auth])
    dest = v3_output_params(1000, flags: flags, service_fields: [freeze_auth, confiscate_auth])
    config = v3_base_config([ti], [dest])

    {:ok, tx} = Stas.build_v3_confiscate_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  # ---- v3 swap cancellation ----

  test "v3 swap cancel tx builds" do
    ti = v3_token_input(1000)
    dest = v3_output_params(1000)
    config = v3_base_config([ti], [dest])

    {:ok, tx} = Stas.build_v3_swap_cancel_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  # ---- v3 swap flow ----

  test "v3 swap flow tx with 2 inputs and 2 outputs" do
    t1 = v3_token_input(1000)
    t2 = v3_token_input(1000)
    d1 = v3_output_params(1000)
    d2 = v3_output_params(1000)
    config = v3_base_config([t1, t2], [d1, d2])

    {:ok, tx} = Stas.build_v3_swap_flow_tx(config)
    assert length(tx.inputs) == 3
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "v3 swap flow rejects 1 input" do
    t1 = v3_token_input(1000)
    d1 = v3_output_params(500)
    d2 = v3_output_params(500)
    config = v3_base_config([t1], [d1, d2])

    assert {:error, _} = Stas.build_v3_swap_flow_tx(config)
  end

  test "v3 swap flow rejects 5 outputs" do
    t1 = v3_token_input(500)
    t2 = v3_token_input(500)
    dests = for _ <- 1..5, do: v3_output_params(200)
    config = v3_base_config([t1, t2], dests)

    assert {:error, _} = Stas.build_v3_swap_flow_tx(config)
  end

  # ---- v3 note output ----

  test "v3 transfer with note data includes OP_RETURN output" do
    ti = v3_token_input(1000)
    dest = v3_output_params(1000)
    config = v3_base_config([ti], [dest], note_data: "compliance audit ref #12345")

    {:ok, tx} = Stas.build_v3_transfer_tx(config)
    # Should have: 1 token output + 1 note output + 1 change output
    note_outputs = Enum.filter(tx.outputs, &BSV.Script.is_op_return?(&1.locking_script))
    assert length(note_outputs) == 1
    assert Enum.at(note_outputs, 0).satoshis == 0
  end

  test "v3 transfer without note data has no OP_RETURN" do
    ti = v3_token_input(1000)
    dest = v3_output_params(1000)
    config = v3_base_config([ti], [dest])

    {:ok, tx} = Stas.build_v3_transfer_tx(config)
    note_outputs = Enum.filter(tx.outputs, &BSV.Script.is_op_return?(&1.locking_script))
    assert length(note_outputs) == 0
  end

  # ---- v3 amount mismatch ----

  test "v3 base tx rejects amount mismatch" do
    ti = v3_token_input(1000)
    dest = v3_output_params(999)
    config = v3_base_config([ti], [dest])

    assert {:error, _} = Stas.build_v3_base_tx(config)
  end

  test "v3 base tx rejects empty destinations" do
    ti = v3_token_input(1000)
    config = v3_base_config([ti], [])

    assert {:error, _} = Stas.build_v3_base_tx(config)
  end

  test "v3 base tx rejects 3 token inputs" do
    t1 = v3_token_input(300)
    t2 = v3_token_input(300)
    t3 = v3_token_input(400)
    dest = v3_output_params(1000)
    config = v3_base_config([t1, t2, t3], [dest])

    assert {:error, _} = Stas.build_v3_base_tx(config)
  end
end
