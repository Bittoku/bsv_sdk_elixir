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

  # Helper to build a DSTAS locking script with swap action data
  defp make_dstas_swap_locking(owner_pkh, redemption_pkh, swap_fields) do
    {:ok, script} =
      DstasBuilder.build_dstas_locking_script(
        owner_pkh,
        redemption_pkh,
        {:swap, swap_fields},
        false,
        true,
        [],
        []
      )

    script
  end

  # Helper to build a frozen DSTAS locking script
  defp make_dstas_frozen_locking(owner_pkh, redemption_pkh) do
    {:ok, script} =
      DstasBuilder.build_dstas_locking_script(owner_pkh, redemption_pkh, nil, true, true, [], [])

    script
  end

  # Helper: build swap action data fields with a given script hash, pkh, and rate
  defp swap_fields(requested_script_hash, requested_pkh, num, den) do
    %{
      requested_script_hash: requested_script_hash,
      requested_pkh: requested_pkh,
      rate_numerator: num,
      rate_denominator: den
    }
  end

  # Helper: make a base swap config with 2 inputs and N destinations
  defp make_swap_config(inputs, destinations, fee_key) do
    %{
      token_inputs: inputs,
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: destinations,
      spend_type: :transfer,
      fee_rate: 500
    }
  end

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
          redemption_pkh: :binary.copy(<<0x22>>, 20)
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Dstas.build_dstas_swap_flow_tx(config)
  end

  test "swap flow with two inputs (auto-detect transfer-swap)" do
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
          redemption_pkh: redemption_pkh
        },
        %DstasOutputParams{
          satoshis: 7_000,
          owner_pkh: :binary.copy(<<0x55>>, 20),
          redemption_pkh: redemption_pkh
        }
      ],
      spend_type: :swap_cancellation,
      fee_rate: 500
    }

    {:ok, tx} = Dstas.build_dstas_swap_flow_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 2
  end

  # ---- Swap action data encoding/decoding tests ----

  test "swap action data encode/decode round-trip" do
    hash = :crypto.strong_rand_bytes(32)
    pkh = :crypto.strong_rand_bytes(20)

    fields = %{
      requested_script_hash: hash,
      requested_pkh: pkh,
      rate_numerator: 1,
      rate_denominator: 2
    }

    encoded = DstasBuilder.encode_swap_action_data(fields)
    assert byte_size(encoded) == 61
    assert <<0x01, _::binary>> = encoded

    {:ok, decoded} = DstasBuilder.decode_swap_action_data(encoded)
    assert decoded.requested_script_hash == hash
    assert decoded.requested_pkh == pkh
    assert decoded.rate_numerator == 1
    assert decoded.rate_denominator == 2
  end

  test "swap action data cancellation sentinel (0/0)" do
    fields = %{
      requested_script_hash: :binary.copy(<<0>>, 32),
      requested_pkh: :binary.copy(<<0>>, 20),
      rate_numerator: 0,
      rate_denominator: 0
    }

    encoded = DstasBuilder.encode_swap_action_data(fields)
    {:ok, decoded} = DstasBuilder.decode_swap_action_data(encoded)
    assert decoded.rate_numerator == 0
    assert decoded.rate_denominator == 0
  end

  test "swap action data embedded in locking script round-trips through reader" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)
    hash = :crypto.strong_rand_bytes(32)
    pkh = :binary.copy(<<0x33>>, 20)

    swap = swap_fields(hash, pkh, 3, 4)
    script = make_dstas_swap_locking(owner_pkh, redemption_pkh, swap)

    parsed = Reader.read_locking_script(Script.to_binary(script))
    assert parsed.script_type == :dstas
    assert {:swap, decoded_swap} = parsed.dstas.action_data_parsed
    assert decoded_swap.requested_script_hash == hash
    assert decoded_swap.requested_pkh == pkh
    assert decoded_swap.rate_numerator == 3
    assert decoded_swap.rate_denominator == 4
  end

  # ---- compute_dstas_requested_script_hash tests ----

  test "compute_dstas_requested_script_hash produces consistent hash" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)
    script = make_dstas_locking(owner_pkh, redemption_pkh)
    script_bin = Script.to_binary(script)

    hash1 = DstasBuilder.compute_dstas_requested_script_hash(script_bin)
    hash2 = DstasBuilder.compute_dstas_requested_script_hash(script_bin)

    assert byte_size(hash1) == 32
    assert hash1 == hash2
  end

  test "different owners produce different script hashes (same tail)" do
    redemption_pkh = :binary.copy(<<0x22>>, 20)
    script_a = make_dstas_locking(:binary.copy(<<0x11>>, 20), redemption_pkh)
    script_b = make_dstas_locking(:binary.copy(<<0x33>>, 20), redemption_pkh)

    hash_a = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(script_a))
    hash_b = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(script_b))

    # Same tail (same redemption, flags, etc.) → same hash
    assert hash_a == hash_b
  end

  test "different redemption PKHs produce different script hashes" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    script_a = make_dstas_locking(owner_pkh, :binary.copy(<<0x22>>, 20))
    script_b = make_dstas_locking(owner_pkh, :binary.copy(<<0x33>>, 20))

    hash_a = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(script_a))
    hash_b = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(script_b))

    # Different tail (different redemption) → different hash
    assert hash_a != hash_b
  end

  test "extract_dstas_script_tail skips owner and action_data" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    # Neutral script (action_data = OP_FALSE)
    neutral = make_dstas_locking(owner_pkh, redemption_pkh)
    neutral_bin = Script.to_binary(neutral)
    tail_neutral = DstasBuilder.extract_dstas_script_tail(neutral_bin)

    # Swap script (action_data = 61-byte swap leg)
    swap = swap_fields(:binary.copy(<<0xAA>>, 32), :binary.copy(<<0xBB>>, 20), 1, 1)
    swap_script = make_dstas_swap_locking(owner_pkh, redemption_pkh, swap)
    swap_bin = Script.to_binary(swap_script)
    tail_swap = DstasBuilder.extract_dstas_script_tail(swap_bin)

    # Both should produce the same tail (owner and action_data are stripped)
    assert tail_neutral == tail_swap
  end

  # ---- Swap mode detection tests ----

  test "resolve_dstas_swap_mode detects transfer-swap (no swap inputs)" do
    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script: make_dstas_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 5_000,
        locking_script: make_dstas_locking(:binary.copy(<<0x33>>, 20), :binary.copy(<<0x22>>, 20)),
        private_key: test_key()
      }
    ]

    assert Dstas.resolve_dstas_swap_mode(inputs) == :transfer_swap
  end

  test "resolve_dstas_swap_mode detects transfer-swap (one swap input)" do
    hash = :binary.copy(<<0xAA>>, 32)
    pkh = :binary.copy(<<0xBB>>, 20)
    swap = swap_fields(hash, pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script:
          make_dstas_swap_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20), swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 5_000,
        locking_script: make_dstas_locking(:binary.copy(<<0x33>>, 20), :binary.copy(<<0x22>>, 20)),
        private_key: test_key()
      }
    ]

    assert Dstas.resolve_dstas_swap_mode(inputs) == :transfer_swap
  end

  test "resolve_dstas_swap_mode detects swap-swap (both swap inputs)" do
    hash = :binary.copy(<<0xAA>>, 32)
    pkh = :binary.copy(<<0xBB>>, 20)
    swap = swap_fields(hash, pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script:
          make_dstas_swap_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20), swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 5_000,
        locking_script:
          make_dstas_swap_locking(:binary.copy(<<0x33>>, 20), :binary.copy(<<0x22>>, 20), swap),
        private_key: test_key()
      }
    ]

    assert Dstas.resolve_dstas_swap_mode(inputs) == :swap_swap
  end

  # ---- Transfer-swap tests ----

  test "transfer-swap with 1:1 rate (2 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    # Bob's token A has swap action data
    cat_script = make_dstas_locking(cat_pkh, redemption_b)
    cat_script_hash =
      DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(cat_script))

    swap = swap_fields(cat_script_hash, bob_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption_a, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: cat_script,
        private_key: test_key()
      }
    ]

    # Principal outputs: ownership exchanged, neutral action data
    destinations = [
      %DstasOutputParams{
        satoshis: 100,
        owner_pkh: bob_pkh,
        redemption_pkh: redemption_b
      },
      %DstasOutputParams{
        satoshis: 100,
        owner_pkh: cat_pkh,
        redemption_pkh: redemption_a
      }
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_transfer_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 2

    # Verify principal outputs have neutral action data
    Enum.take(tx.outputs, 2)
    |> Enum.each(fn out ->
      parsed = Reader.read_locking_script(Script.to_binary(out.locking_script))
      assert parsed.script_type == :dstas
      assert parsed.dstas.action_data_parsed == nil
    end)
  end

  test "swap-swap with 1:1 rate (2 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    # Build scripts to compute hashes
    bob_script = make_dstas_locking(bob_pkh, redemption_a)
    cat_script = make_dstas_locking(cat_pkh, redemption_b)
    bob_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(bob_script))
    cat_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(cat_script))

    # Both have swap action data requesting each other
    swap_a = swap_fields(cat_hash, bob_pkh, 1, 1)
    swap_b = swap_fields(bob_hash, cat_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption_a, swap_a),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(cat_pkh, redemption_b, swap_b),
        private_key: test_key()
      }
    ]

    destinations = [
      %DstasOutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_swap_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 2
  end

  # ---- Transfer-swap with remainder tests ----

  test "transfer-swap with fractional rate + 1 remainder (3 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    cat_script = make_dstas_locking(cat_pkh, redemption_b)
    cat_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(cat_script))

    # Rate 1:2 — Bob swaps 100 A for 50 B; Cat gets 100 A, remainder 50 B back to Cat
    swap = swap_fields(cat_hash, bob_pkh, 1, 2)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption_a, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: cat_script,
        private_key: test_key()
      }
    ]

    # 3 outputs: 50 B→Bob, 100 A→Cat, 50 B remainder→Cat
    destinations = [
      %DstasOutputParams{satoshis: 50, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %DstasOutputParams{satoshis: 50, owner_pkh: cat_pkh, redemption_pkh: redemption_b}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_transfer_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 3
  end

  test "swap-swap with fractional rate + 1 remainder (3 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    bob_script = make_dstas_locking(bob_pkh, redemption_a)
    cat_script = make_dstas_locking(cat_pkh, redemption_b)
    bob_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(bob_script))
    cat_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(cat_script))

    swap_a = swap_fields(cat_hash, bob_pkh, 1, 2)
    swap_b = swap_fields(bob_hash, cat_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption_a, swap_a),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(cat_pkh, redemption_b, swap_b),
        private_key: test_key()
      }
    ]

    destinations = [
      %DstasOutputParams{satoshis: 50, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %DstasOutputParams{satoshis: 50, owner_pkh: cat_pkh, redemption_pkh: redemption_b}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_swap_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 3
  end

  test "transfer-swap with 2 remainders (4 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    cat_script = make_dstas_locking(cat_pkh, redemption_b)
    cat_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(cat_script))

    swap = swap_fields(cat_hash, bob_pkh, 1, 2)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption_a, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: cat_script,
        private_key: test_key()
      }
    ]

    # 4 outputs: principals + 2 remainders
    destinations = [
      %DstasOutputParams{satoshis: 40, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 80, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %DstasOutputParams{satoshis: 60, owner_pkh: cat_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 20, owner_pkh: bob_pkh, redemption_pkh: redemption_a}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_transfer_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 4
  end

  test "swap-swap with 2 remainders (4 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    bob_script = make_dstas_locking(bob_pkh, redemption_a)
    cat_script = make_dstas_locking(cat_pkh, redemption_b)
    bob_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(bob_script))
    cat_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(cat_script))

    swap_a = swap_fields(cat_hash, bob_pkh, 1, 2)
    swap_b = swap_fields(bob_hash, cat_pkh, 2, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption_a, swap_a),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(cat_pkh, redemption_b, swap_b),
        private_key: test_key()
      }
    ]

    destinations = [
      %DstasOutputParams{satoshis: 40, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 80, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %DstasOutputParams{satoshis: 60, owner_pkh: cat_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 20, owner_pkh: bob_pkh, redemption_pkh: redemption_a}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_swap_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 4
  end

  # ---- Frozen input rejection tests ----

  test "transfer-swap rejects frozen input" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_frozen_locking(bob_pkh, redemption),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_dstas_locking(:binary.copy(<<0x33>>, 20), redemption),
        private_key: test_key()
      }
    ]

    destinations = [
      %DstasOutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %DstasOutputParams{
        satoshis: 100,
        owner_pkh: :binary.copy(<<0x33>>, 20),
        redemption_pkh: redemption
      }
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    assert {:error, _} = Dstas.build_dstas_transfer_swap_tx(config)
  end

  test "swap-swap rejects frozen input" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    hash = :binary.copy(<<0xAA>>, 32)
    swap = swap_fields(hash, bob_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        # Frozen — can't have swap action data AND be frozen simultaneously via builder,
        # but we test the frozen check by using a frozen locking script
        locking_script: make_dstas_frozen_locking(bob_pkh, redemption),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(cat_pkh, redemption, swap),
        private_key: test_key()
      }
    ]

    destinations = [
      %DstasOutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %DstasOutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    assert {:error, _} = Dstas.build_dstas_swap_swap_tx(config)
  end

  # ---- Swap auto-detection integration tests ----

  test "swap flow auto-detects swap-swap when both inputs have swap data" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    hash = :binary.copy(<<0xAA>>, 32)
    swap = swap_fields(hash, bob_pkh, 1, 1)
    swap2 = swap_fields(hash, cat_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(cat_pkh, redemption, swap2),
        private_key: test_key()
      }
    ]

    destinations = [
      %DstasOutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %DstasOutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_swap_flow_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 2
  end

  test "swap flow auto-detects transfer-swap when one input has swap data" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    hash = :binary.copy(<<0xAA>>, 32)
    swap = swap_fields(hash, bob_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_dstas_locking(cat_pkh, redemption),
        private_key: test_key()
      }
    ]

    destinations = [
      %DstasOutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %DstasOutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_swap_flow_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 2
  end

  # ---- Swap with action data in remainder outputs ----

  test "remainder outputs can carry inherited swap action data" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    cat_script = make_dstas_locking(cat_pkh, redemption_b)
    cat_hash = DstasBuilder.compute_dstas_requested_script_hash(Script.to_binary(cat_script))

    swap = swap_fields(cat_hash, bob_pkh, 1, 2)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_dstas_swap_locking(bob_pkh, redemption_a, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: cat_script,
        private_key: test_key()
      }
    ]

    # Remainder output at index 2 inherits swap action data from leg 1
    destinations = [
      %DstasOutputParams{satoshis: 50, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %DstasOutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %DstasOutputParams{
        satoshis: 50,
        owner_pkh: cat_pkh,
        redemption_pkh: redemption_b,
        action_data: {:swap, swap}
      }
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Dstas.build_dstas_transfer_swap_tx(config)

    # Verify the remainder output has swap action data
    remainder_out = Enum.at(tx.outputs, 2)
    parsed = Reader.read_locking_script(Script.to_binary(remainder_out.locking_script))
    assert parsed.script_type == :dstas
    assert {:swap, remainder_swap} = parsed.dstas.action_data_parsed
    assert remainder_swap.requested_script_hash == cat_hash
    assert remainder_swap.rate_numerator == 1
    assert remainder_swap.rate_denominator == 2
  end
end
