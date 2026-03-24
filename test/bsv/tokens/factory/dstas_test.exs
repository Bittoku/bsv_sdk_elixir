defmodule BSV.Tokens.Factory.DstasTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Crypto, Script}
  alias BSV.Transaction
  alias BSV.Tokens.Factory.Dstas
  alias BSV.Tokens.Script.{DstasBuilder, Reader}
  alias BSV.Tokens.{Scheme, Authority, TokenId, TokenInput, DstasOutputParams}

  defp test_key, do: PrivateKey.generate()

  defp p2pkh_script(key) do
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    address = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, script} = BSV.Script.Address.to_script(address)
    script
  end

  defp dummy_hash, do: :binary.copy(<<0xAA>>, 32)

  defp test_scheme do
    %Scheme{
      name: "TestDSTAS",
      token_id: TokenId.from_pkh(:binary.copy(<<0xAA>>, 20)),
      symbol: "TDSTAS",
      satoshis_per_token: 1,
      freeze: true,
      confiscation: false,
      is_divisible: true,
      authority: %Authority{m: 1, public_keys: ["02abcdef"]}
    }
  end

  defp make_dstas_locking(owner_pkh, redemption_pkh) do
    {:ok, script} =
      DstasBuilder.build_dstas_locking_script(owner_pkh, redemption_pkh, nil, false, true, [], [])

    script
  end

  # ---- Issue flow tests ----

  test "issue txs structure" do
    key = test_key()

    config = %{
      scheme: test_scheme(),
      funding_txid: dummy_hash(),
      funding_vout: 0,
      funding_satoshis: 100_000,
      funding_locking_script: p2pkh_script(key),
      funding_private_key: key,
      outputs: [
        %{satoshis: 5_000, owner_pkh: :binary.copy(<<0x11>>, 20), freezable: true},
        %{satoshis: 5_000, owner_pkh: :binary.copy(<<0x22>>, 20), freezable: false}
      ],
      fee_rate: 500
    }

    {:ok, result} = Dstas.build_dstas_issue_txs(config)

    assert length(result.contract_tx.inputs) == 1
    assert length(result.contract_tx.outputs) >= 2
    assert Enum.at(result.contract_tx.outputs, 0).satoshis == 10_000
    assert Enum.at(result.contract_tx.outputs, 1).satoshis == 0

    assert length(result.issue_tx.inputs) >= 1
    assert length(result.issue_tx.outputs) >= 2
    assert Enum.at(result.issue_tx.outputs, 0).satoshis == 5_000
    assert Enum.at(result.issue_tx.outputs, 1).satoshis == 5_000

    assert Enum.all?(result.contract_tx.inputs, &(&1.unlocking_script != nil))
    assert Enum.all?(result.issue_tx.inputs, &(&1.unlocking_script != nil))
  end

  test "issue txid chaining" do
    key = test_key()

    config = %{
      scheme: test_scheme(),
      funding_txid: dummy_hash(),
      funding_vout: 0,
      funding_satoshis: 100_000,
      funding_locking_script: p2pkh_script(key),
      funding_private_key: key,
      outputs: [%{satoshis: 10_000, owner_pkh: :binary.copy(<<0x11>>, 20), freezable: true}],
      fee_rate: 500
    }

    {:ok, result} = Dstas.build_dstas_issue_txs(config)
    contract_txid = Transaction.tx_id(result.contract_tx)
    assert hd(result.issue_tx.inputs).source_txid == contract_txid
  end

  test "issue empty outputs rejected" do
    key = test_key()

    config = %{
      scheme: test_scheme(),
      funding_txid: dummy_hash(),
      funding_vout: 0,
      funding_satoshis: 100_000,
      funding_locking_script: p2pkh_script(key),
      funding_private_key: key,
      outputs: [],
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_issue_txs(config)
  end

  test "issue insufficient funds" do
    key = test_key()

    config = %{
      scheme: test_scheme(),
      funding_txid: dummy_hash(),
      funding_vout: 0,
      funding_satoshis: 100,
      funding_locking_script: p2pkh_script(key),
      funding_private_key: key,
      outputs: [%{satoshis: 10_000, owner_pkh: :binary.copy(<<0x11>>, 20), freezable: true}],
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_issue_txs(config)
  end

  # ---- Base TX tests ----

  test "base tx structure" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_base_tx(config)
    assert length(tx.inputs) == 2
    assert length(tx.outputs) >= 1
    assert Enum.at(tx.outputs, 0).satoshis == 5_000
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "base tx amount mismatch" do
    token_key = test_key()
    fee_key = test_key()

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 10_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 9_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: :binary.copy(<<0x22>>, 20),
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_base_tx(config)
  end

  test "base tx empty destinations" do
    token_key = test_key()
    fee_key = test_key()

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_base_tx(config)
  end

  # ---- Freeze / Unfreeze tests ----

  test "freeze tx output is frozen" do
    token_key = test_key()
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_freeze_tx(config)
    parsed = Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 0).locking_script))
    assert parsed.script_type == :dstas
    assert parsed.dstas.frozen == true
  end

  test "unfreeze tx output is not frozen" do
    token_key = test_key()
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: true,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_unfreeze_tx(config)
    parsed = Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 0).locking_script))
    assert parsed.script_type == :dstas
    assert parsed.dstas.frozen == false
  end

  # ---- Split tests ----

  test "split tx with 1 input and 2 destinations" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 10_000,
          locking_script: make_dstas_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 4_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        },
        %DstasOutputParams{
          satoshis: 6_000,
          owner_pkh: :binary.copy(<<0x44>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_split_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.at(tx.outputs, 0).satoshis == 4_000
    assert Enum.at(tx.outputs, 1).satoshis == 6_000
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "split tx with 4 destinations (max)" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    dests =
      for i <- 1..4 do
        %DstasOutputParams{
          satoshis: 2_500,
          owner_pkh: :binary.copy(<<i>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      end

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 10_000,
          locking_script: make_dstas_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: dests,
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_split_tx(config)
    dstas_outputs = Enum.take(tx.outputs, 4)
    assert length(dstas_outputs) == 4
    assert Enum.all?(dstas_outputs, &(&1.satoshis == 2_500))
  end

  test "split rejects 2 STAS inputs" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 5_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 10_000,
          owner_pkh: :binary.copy(<<0x44>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_split_tx(config)
  end

  test "split rejects 5 destinations" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    dests =
      for i <- 1..5 do
        %DstasOutputParams{
          satoshis: 2_000,
          owner_pkh: :binary.copy(<<i>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      end

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 10_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: dests,
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_split_tx(config)
  end

  test "split rejects conservation violation" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 10_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 8_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_split_tx(config)
  end

  # ---- Merge tests ----

  test "merge tx with 2 inputs and 1 destination" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 3_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 7_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 10_000,
          owner_pkh: :binary.copy(<<0x44>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_merge_tx(config)
    assert length(tx.inputs) == 3
    assert Enum.at(tx.outputs, 0).satoshis == 10_000
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "merge rejects 1 STAS input" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_merge_tx(config)
  end

  test "merge rejects 3 destinations" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    dests =
      for i <- 1..3 do
        %DstasOutputParams{
          satoshis: 2_000,
          owner_pkh: :binary.copy(<<i>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      end

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 3_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 3_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: dests,
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_merge_tx(config)
  end

  # ---- Confiscation tests ----

  test "confiscation tx structure" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x55>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_confiscate_tx(config)
    assert length(tx.inputs) == 2
    assert Enum.at(tx.outputs, 0).satoshis == 5_000
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "confiscation rejects empty destinations" do
    fee_key = test_key()

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script:
            make_dstas_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_confiscate_tx(config)
  end

  # ---- Redeem tests ----

  test "redeem tx produces P2PKH output" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    # Build a DSTAS script where owner == redemption (issuer holds the token)
    dstas_script = make_dstas_locking(issuer_pkh, issuer_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 10_000,
        locking_script: dstas_script,
        private_key: token_key
      },
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      redeem_satoshis: 10_000,
      redeem_pkh: issuer_pkh,
      remaining_destinations: [],
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_redeem_tx(config)
    assert length(tx.inputs) == 2
    # First output should be P2PKH (25 bytes)
    redeem_out = Enum.at(tx.outputs, 0)
    assert redeem_out.satoshis == 10_000
    redeem_bin = Script.to_binary(redeem_out.locking_script)
    assert byte_size(redeem_bin) == 25
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "redeem with remaining DSTAS outputs" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    dstas_script = make_dstas_locking(issuer_pkh, issuer_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 10_000,
        locking_script: dstas_script,
        private_key: token_key
      },
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      redeem_satoshis: 6_000,
      redeem_pkh: issuer_pkh,
      remaining_destinations: [
        %DstasOutputParams{
          satoshis: 4_000,
          owner_pkh: issuer_pkh,
          redemption_pkh: issuer_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_redeem_tx(config)
    assert Enum.at(tx.outputs, 0).satoshis == 6_000
    assert Enum.at(tx.outputs, 1).satoshis == 4_000
    # Second output should be DSTAS
    parsed = Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 1).locking_script))
    assert parsed.script_type == :dstas
  end

  test "redeem rejects non-issuer owner" do
    token_key = test_key()
    fee_key = test_key()
    non_issuer_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    # Owner != redemption, so not the issuer
    dstas_script = make_dstas_locking(non_issuer_pkh, redemption_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script: dstas_script,
        private_key: token_key
      },
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      redeem_satoshis: 5_000,
      redeem_pkh: redemption_pkh,
      remaining_destinations: [],
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_redeem_tx(config)
  end

  test "redeem rejects frozen input" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    # Build a frozen DSTAS script (owner == redemption, but frozen)
    {:ok, frozen_script} =
      DstasBuilder.build_dstas_locking_script(issuer_pkh, issuer_pkh, nil, true, true, [], [])

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script: frozen_script,
        private_key: token_key
      },
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      redeem_satoshis: 5_000,
      redeem_pkh: issuer_pkh,
      remaining_destinations: [],
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_redeem_tx(config)
  end

  test "redeem rejects conservation violation" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    dstas_script = make_dstas_locking(issuer_pkh, issuer_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 10_000,
        locking_script: dstas_script,
        private_key: token_key
      },
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      redeem_satoshis: 8_000,
      redeem_pkh: issuer_pkh,
      remaining_destinations: [],
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_redeem_tx(config)
  end

  # ---- Swap flow tests ----

  test "swap flow requires two inputs" do
    fee_key = test_key()

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: :binary.copy(<<0x22>>, 20),
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_swap_flow_tx(config)
  end

  test "swap flow with two inputs" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 3_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 7_000,
          locking_script: make_dstas_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %DstasOutputParams{
          satoshis: 3_000,
          owner_pkh: :binary.copy(<<0x44>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        },
        %DstasOutputParams{
          satoshis: 7_000,
          owner_pkh: :binary.copy(<<0x55>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        }
      ],
      spend_type: :swap_cancellation,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_swap_flow_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 2
  end
end
