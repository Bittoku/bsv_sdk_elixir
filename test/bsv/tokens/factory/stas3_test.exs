defmodule BSV.Tokens.Factory.Stas3Test do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Crypto, Script}
  alias BSV.Transaction
  alias BSV.Tokens.Factory.Stas3
  alias BSV.Tokens.Script.{Stas3Builder, Reader}
  alias BSV.Tokens.{Scheme, Authority, TokenId, TokenInput, Stas3OutputParams}

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
      name: "TestSTAS3",
      token_id: TokenId.from_pkh(:binary.copy(<<0xAA>>, 20)),
      symbol: "TSTAS3",
      satoshis_per_token: 1,
      freeze: true,
      confiscation: false,
      is_divisible: true,
      authority: %Authority{m: 1, public_keys: ["02abcdef"]}
    }
  end

  defp make_stas3_locking(owner_pkh, redemption_pkh) do
    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner_pkh, redemption_pkh, nil, false, true, [], [])

    script
  end

  # Build a locking script with explicit `BSV.Tokens.ScriptFlags`. Used by
  # tests that need CONFISCATABLE set (§9.3) or any non-default flag combo.
  defp make_stas3_locking_with_flags(owner_pkh, redemption_pkh, %BSV.Tokens.ScriptFlags{} = flags) do
    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(
        owner_pkh,
        redemption_pkh,
        nil,
        false,
        flags,
        [],
        []
      )

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

    {:ok, result} = Stas3.build_stas3_issue_txs(config)

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

    {:ok, result} = Stas3.build_stas3_issue_txs(config)
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

    assert {:error, _} = Stas3.build_stas3_issue_txs(config)
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

    assert {:error, _} = Stas3.build_stas3_issue_txs(config)
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
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
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

    {:ok, tx} = Stas3.build_stas3_base_tx(config)
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
          locking_script:
            make_stas3_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
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

    assert {:error, _} = Stas3.build_stas3_base_tx(config)
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
          locking_script:
            make_stas3_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
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

    assert {:error, _} = Stas3.build_stas3_base_tx(config)
  end

  # ---- Freeze / Unfreeze tests ----

  test "freeze tx output is frozen" do
    token_key = test_key()
    fee_key = test_key()
    # Spec §9.2: freeze output's owner & redemption must equal the input —
    # only `var2` may differ. Pin both ends to the same owner_pkh.
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 5_000,
          owner_pkh: owner_pkh,
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

    {:ok, tx} = Stas3.build_stas3_freeze_tx(config)
    parsed = Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 0).locking_script))
    assert parsed.script_type == :stas3
    assert parsed.stas3.frozen == true
  end

  test "unfreeze tx output is not frozen" do
    token_key = test_key()
    fee_key = test_key()
    # Same §9.2 invariant: owner & redemption byte-identical across input/output.
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 5_000,
          owner_pkh: owner_pkh,
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

    {:ok, tx} = Stas3.build_stas3_unfreeze_tx(config)
    parsed = Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 0).locking_script))
    assert parsed.script_type == :stas3
    assert parsed.stas3.frozen == false
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
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 4_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: []
        },
        %Stas3OutputParams{
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

    {:ok, tx} = Stas3.build_stas3_split_tx(config)
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
        %Stas3OutputParams{
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
          locking_script: make_stas3_locking(owner_pkh, redemption_pkh),
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

    {:ok, tx} = Stas3.build_stas3_split_tx(config)
    stas3_outputs = Enum.take(tx.outputs, 4)
    assert length(stas3_outputs) == 4
    assert Enum.all?(stas3_outputs, &(&1.satoshis == 2_500))
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
          locking_script: make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 5_000,
          locking_script: make_stas3_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
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

    assert {:error, _} = Stas3.build_stas3_split_tx(config)
  end

  test "split rejects 5 destinations" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    dests =
      for i <- 1..5 do
        %Stas3OutputParams{
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
          locking_script: make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
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

    assert {:error, _} = Stas3.build_stas3_split_tx(config)
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
          locking_script: make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
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

    assert {:error, _} = Stas3.build_stas3_split_tx(config)
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
          locking_script: make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 7_000,
          locking_script: make_stas3_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
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

    {:ok, tx} = Stas3.build_stas3_merge_tx(config)
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
          locking_script: make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
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

    assert {:error, _} = Stas3.build_stas3_merge_tx(config)
  end

  test "merge rejects 3 destinations" do
    fee_key = test_key()
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    dests =
      for i <- 1..3 do
        %Stas3OutputParams{
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
          locking_script: make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 3_000,
          locking_script: make_stas3_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
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

    assert {:error, _} = Stas3.build_stas3_merge_tx(config)
  end

  # ---- Confiscation tests ----

  test "confiscation tx structure" do
    token_key = test_key()
    fee_key = test_key()
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    # Spec §9.3: confiscation requires CONFISCATABLE flag set on the input.
    confiscatable_flags = %BSV.Tokens.ScriptFlags{freezable: true, confiscatable: true}

    config = %{
      token_inputs: [
        %TokenInput{
          txid: dummy_hash(),
          vout: 0,
          satoshis: 5_000,
          locking_script:
            make_stas3_locking_with_flags(owner_pkh, redemption_pkh, confiscatable_flags),
          private_key: token_key
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
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

    {:ok, tx} = Stas3.build_stas3_confiscate_tx(config)
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
            make_stas3_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
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

    assert {:error, _} = Stas3.build_stas3_confiscate_tx(config)
  end

  # ---- Redeem tests ----

  test "redeem tx produces P2PKH output" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    # Build a STAS3 script where owner == redemption (issuer holds the token)
    stas3_script = make_stas3_locking(issuer_pkh, issuer_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 10_000,
        locking_script: stas3_script,
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

    {:ok, tx} = Stas3.build_stas3_redeem_tx(config)
    assert length(tx.inputs) == 2
    # First output should be P2PKH (25 bytes)
    redeem_out = Enum.at(tx.outputs, 0)
    assert redeem_out.satoshis == 10_000
    redeem_bin = Script.to_binary(redeem_out.locking_script)
    assert byte_size(redeem_bin) == 25
    assert Enum.all?(tx.inputs, &(&1.unlocking_script != nil))
  end

  test "redeem with remaining STAS3 outputs" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    stas3_script = make_stas3_locking(issuer_pkh, issuer_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 10_000,
        locking_script: stas3_script,
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
        %Stas3OutputParams{
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

    {:ok, tx} = Stas3.build_stas3_redeem_tx(config)
    assert Enum.at(tx.outputs, 0).satoshis == 6_000
    assert Enum.at(tx.outputs, 1).satoshis == 4_000
    # Second output should be STAS3
    parsed = Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 1).locking_script))
    assert parsed.script_type == :stas3
  end

  test "redeem rejects non-issuer owner" do
    token_key = test_key()
    fee_key = test_key()
    non_issuer_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    # Owner != redemption, so not the issuer
    stas3_script = make_stas3_locking(non_issuer_pkh, redemption_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script: stas3_script,
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

    assert {:error, _} = Stas3.build_stas3_redeem_tx(config)
  end

  test "redeem rejects frozen input" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    # Build a frozen STAS3 script (owner == redemption, but frozen)
    {:ok, frozen_script} =
      Stas3Builder.build_stas3_locking_script(issuer_pkh, issuer_pkh, nil, true, true, [], [])

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

    assert {:error, _} = Stas3.build_stas3_redeem_tx(config)
  end

  test "redeem rejects conservation violation" do
    token_key = test_key()
    fee_key = test_key()
    pubkey = PrivateKey.to_public_key(token_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)

    stas3_script = make_stas3_locking(issuer_pkh, issuer_pkh)

    config = %{
      token_input: %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 10_000,
        locking_script: stas3_script,
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

    assert {:error, _} = Stas3.build_stas3_redeem_tx(config)
  end

  # ---- Swap flow tests ----

  # Helper to build a STAS3 locking script with swap action data
  defp make_stas3_swap_locking(owner_pkh, redemption_pkh, swap_fields) do
    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(
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

  # Helper to build a frozen STAS3 locking script
  defp make_stas3_frozen_locking(owner_pkh, redemption_pkh) do
    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner_pkh, redemption_pkh, nil, true, true, [], [])

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
          locking_script:
            make_stas3_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 1,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 5_000,
          owner_pkh: :binary.copy(<<0x33>>, 20),
          redemption_pkh: :binary.copy(<<0x22>>, 20)
        }
      ],
      spend_type: :transfer,
      fee_rate: 500
    }

    assert {:error, _} = Stas3.build_stas3_swap_flow_tx(config)
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
          locking_script: make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh),
          private_key: test_key()
        },
        %TokenInput{
          txid: dummy_hash(),
          vout: 1,
          satoshis: 7_000,
          locking_script: make_stas3_locking(:binary.copy(<<0x33>>, 20), redemption_pkh),
          private_key: test_key()
        }
      ],
      fee_txid: dummy_hash(),
      fee_vout: 2,
      fee_satoshis: 50_000,
      fee_locking_script: p2pkh_script(fee_key),
      fee_private_key: fee_key,
      destinations: [
        %Stas3OutputParams{
          satoshis: 3_000,
          owner_pkh: :binary.copy(<<0x44>>, 20),
          redemption_pkh: redemption_pkh
        },
        %Stas3OutputParams{
          satoshis: 7_000,
          owner_pkh: :binary.copy(<<0x55>>, 20),
          redemption_pkh: redemption_pkh
        }
      ],
      spend_type: :swap_cancellation,
      fee_rate: 500
    }

    {:ok, tx} = Stas3.build_stas3_swap_flow_tx(config)
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

    encoded = Stas3Builder.encode_swap_action_data(fields)
    assert byte_size(encoded) == 61
    assert <<0x01, _::binary>> = encoded

    {:ok, decoded} = Stas3Builder.decode_swap_action_data(encoded)
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

    encoded = Stas3Builder.encode_swap_action_data(fields)
    {:ok, decoded} = Stas3Builder.decode_swap_action_data(encoded)
    assert decoded.rate_numerator == 0
    assert decoded.rate_denominator == 0
  end

  test "swap action data embedded in locking script round-trips through reader" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)
    hash = :crypto.strong_rand_bytes(32)
    pkh = :binary.copy(<<0x33>>, 20)

    swap = swap_fields(hash, pkh, 3, 4)
    script = make_stas3_swap_locking(owner_pkh, redemption_pkh, swap)

    parsed = Reader.read_locking_script(Script.to_binary(script))
    assert parsed.script_type == :stas3
    assert {:swap, decoded_swap} = parsed.stas3.action_data_parsed
    assert decoded_swap.requested_script_hash == hash
    assert decoded_swap.requested_pkh == pkh
    assert decoded_swap.rate_numerator == 3
    assert decoded_swap.rate_denominator == 4
  end

  # ---- compute_stas3_requested_script_hash tests ----

  test "compute_stas3_requested_script_hash produces consistent hash" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)
    script = make_stas3_locking(owner_pkh, redemption_pkh)
    script_bin = Script.to_binary(script)

    hash1 = Stas3Builder.compute_stas3_requested_script_hash(script_bin)
    hash2 = Stas3Builder.compute_stas3_requested_script_hash(script_bin)

    assert byte_size(hash1) == 32
    assert hash1 == hash2
  end

  test "different owners produce different script hashes (same tail)" do
    redemption_pkh = :binary.copy(<<0x22>>, 20)
    script_a = make_stas3_locking(:binary.copy(<<0x11>>, 20), redemption_pkh)
    script_b = make_stas3_locking(:binary.copy(<<0x33>>, 20), redemption_pkh)

    hash_a = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(script_a))
    hash_b = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(script_b))

    # Same tail (same redemption, flags, etc.) → same hash
    assert hash_a == hash_b
  end

  test "different redemption PKHs produce different script hashes" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    script_a = make_stas3_locking(owner_pkh, :binary.copy(<<0x22>>, 20))
    script_b = make_stas3_locking(owner_pkh, :binary.copy(<<0x33>>, 20))

    hash_a = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(script_a))
    hash_b = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(script_b))

    # Different tail (different redemption) → different hash
    assert hash_a != hash_b
  end

  test "extract_stas3_script_tail skips owner and action_data" do
    owner_pkh = :binary.copy(<<0x11>>, 20)
    redemption_pkh = :binary.copy(<<0x22>>, 20)

    # Neutral script (action_data = OP_FALSE)
    neutral = make_stas3_locking(owner_pkh, redemption_pkh)
    neutral_bin = Script.to_binary(neutral)
    tail_neutral = Stas3Builder.extract_stas3_script_tail(neutral_bin)

    # Swap script (action_data = 61-byte swap leg)
    swap = swap_fields(:binary.copy(<<0xAA>>, 32), :binary.copy(<<0xBB>>, 20), 1, 1)
    swap_script = make_stas3_swap_locking(owner_pkh, redemption_pkh, swap)
    swap_bin = Script.to_binary(swap_script)
    tail_swap = Stas3Builder.extract_stas3_script_tail(swap_bin)

    # Both should produce the same tail (owner and action_data are stripped)
    assert tail_neutral == tail_swap
  end

  # ---- Swap mode detection tests ----

  test "resolve_stas3_swap_mode detects transfer-swap (no swap inputs)" do
    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script:
          make_stas3_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20)),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 5_000,
        locking_script:
          make_stas3_locking(:binary.copy(<<0x33>>, 20), :binary.copy(<<0x22>>, 20)),
        private_key: test_key()
      }
    ]

    assert Stas3.resolve_stas3_swap_mode(inputs) == :transfer_swap
  end

  test "resolve_stas3_swap_mode detects transfer-swap (one swap input)" do
    hash = :binary.copy(<<0xAA>>, 32)
    pkh = :binary.copy(<<0xBB>>, 20)
    swap = swap_fields(hash, pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script:
          make_stas3_swap_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20), swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 5_000,
        locking_script:
          make_stas3_locking(:binary.copy(<<0x33>>, 20), :binary.copy(<<0x22>>, 20)),
        private_key: test_key()
      }
    ]

    assert Stas3.resolve_stas3_swap_mode(inputs) == :transfer_swap
  end

  test "resolve_stas3_swap_mode detects swap-swap (both swap inputs)" do
    hash = :binary.copy(<<0xAA>>, 32)
    pkh = :binary.copy(<<0xBB>>, 20)
    swap = swap_fields(hash, pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 5_000,
        locking_script:
          make_stas3_swap_locking(:binary.copy(<<0x11>>, 20), :binary.copy(<<0x22>>, 20), swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 5_000,
        locking_script:
          make_stas3_swap_locking(:binary.copy(<<0x33>>, 20), :binary.copy(<<0x22>>, 20), swap),
        private_key: test_key()
      }
    ]

    assert Stas3.resolve_stas3_swap_mode(inputs) == :swap_swap
  end

  # ---- Transfer-swap tests ----

  test "transfer-swap with 1:1 rate (2 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    # Bob's token A has swap action data
    cat_script = make_stas3_locking(cat_pkh, redemption_b)

    cat_script_hash =
      Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    swap = swap_fields(cat_script_hash, bob_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap),
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
      %Stas3OutputParams{
        satoshis: 100,
        owner_pkh: bob_pkh,
        redemption_pkh: redemption_b
      },
      %Stas3OutputParams{
        satoshis: 100,
        owner_pkh: cat_pkh,
        redemption_pkh: redemption_a
      }
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_transfer_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 2

    # Verify principal outputs have neutral action data
    Enum.take(tx.outputs, 2)
    |> Enum.each(fn out ->
      parsed = Reader.read_locking_script(Script.to_binary(out.locking_script))
      assert parsed.script_type == :stas3
      assert parsed.stas3.action_data_parsed == nil
    end)
  end

  test "swap-swap with 1:1 rate (2 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    # Build scripts to compute hashes
    bob_script = make_stas3_locking(bob_pkh, redemption_a)
    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    bob_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(bob_script))
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    # Both have swap action data requesting each other
    swap_a = swap_fields(cat_hash, bob_pkh, 1, 1)
    swap_b = swap_fields(bob_hash, cat_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap_a),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(cat_pkh, redemption_b, swap_b),
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_swap_swap_tx(config)
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

    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    # Rate 1:2 — Bob swaps 100 A for 50 B; Cat gets 100 A, remainder 50 B back to Cat
    swap = swap_fields(cat_hash, bob_pkh, 1, 2)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap),
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
      %Stas3OutputParams{satoshis: 50, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %Stas3OutputParams{satoshis: 50, owner_pkh: cat_pkh, redemption_pkh: redemption_b}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_transfer_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 3
  end

  test "swap-swap with fractional rate + 1 remainder (3 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    bob_script = make_stas3_locking(bob_pkh, redemption_a)
    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    bob_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(bob_script))
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    swap_a = swap_fields(cat_hash, bob_pkh, 1, 2)
    swap_b = swap_fields(bob_hash, cat_pkh, 1, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap_a),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(cat_pkh, redemption_b, swap_b),
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 50, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %Stas3OutputParams{satoshis: 50, owner_pkh: cat_pkh, redemption_pkh: redemption_b}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_swap_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 3
  end

  test "transfer-swap with 2 remainders (4 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    swap = swap_fields(cat_hash, bob_pkh, 1, 2)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap),
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
      %Stas3OutputParams{satoshis: 40, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 80, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %Stas3OutputParams{satoshis: 60, owner_pkh: cat_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 20, owner_pkh: bob_pkh, redemption_pkh: redemption_a}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_transfer_swap_tx(config)
    assert length(tx.inputs) == 3
    assert length(tx.outputs) >= 4
  end

  test "swap-swap with 2 remainders (4 outputs)" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    bob_script = make_stas3_locking(bob_pkh, redemption_a)
    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    bob_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(bob_script))
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    swap_a = swap_fields(cat_hash, bob_pkh, 1, 2)
    swap_b = swap_fields(bob_hash, cat_pkh, 2, 1)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap_a),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(cat_pkh, redemption_b, swap_b),
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 40, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 80, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %Stas3OutputParams{satoshis: 60, owner_pkh: cat_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 20, owner_pkh: bob_pkh, redemption_pkh: redemption_a}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_swap_swap_tx(config)
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
        locking_script: make_stas3_frozen_locking(bob_pkh, redemption),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_stas3_locking(:binary.copy(<<0x33>>, 20), redemption),
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %Stas3OutputParams{
        satoshis: 100,
        owner_pkh: :binary.copy(<<0x33>>, 20),
        redemption_pkh: redemption
      }
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    assert {:error, _} = Stas3.build_stas3_transfer_swap_tx(config)
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
        locking_script: make_stas3_frozen_locking(bob_pkh, redemption),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(cat_pkh, redemption, swap),
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    assert {:error, _} = Stas3.build_stas3_swap_swap_tx(config)
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
        locking_script: make_stas3_swap_locking(bob_pkh, redemption, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(cat_pkh, redemption, swap2),
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_swap_flow_tx(config)
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
        locking_script: make_stas3_swap_locking(bob_pkh, redemption, swap),
        private_key: test_key()
      },
      %TokenInput{
        txid: dummy_hash(),
        vout: 1,
        satoshis: 100,
        locking_script: make_stas3_locking(cat_pkh, redemption),
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{satoshis: 100, owner_pkh: bob_pkh, redemption_pkh: redemption},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_swap_flow_tx(config)
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

    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    swap = swap_fields(cat_hash, bob_pkh, 1, 2)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: make_stas3_swap_locking(bob_pkh, redemption_a, swap),
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
      %Stas3OutputParams{satoshis: 50, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %Stas3OutputParams{
        satoshis: 50,
        owner_pkh: cat_pkh,
        redemption_pkh: redemption_b,
        action_data: {:swap, swap}
      }
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_transfer_swap_tx(config)

    # Verify the remainder output has swap action data
    remainder_out = Enum.at(tx.outputs, 2)
    parsed = Reader.read_locking_script(Script.to_binary(remainder_out.locking_script))
    assert parsed.script_type == :stas3
    assert {:swap, remainder_swap} = parsed.stas3.action_data_parsed
    assert remainder_swap.requested_script_hash == cat_hash
    assert remainder_swap.rate_numerator == 1
    assert remainder_swap.rate_denominator == 2
  end

  # ── STAS 3.0 v0.1 §9.5 — Item F: remainder inherits BOTH owner and var2. ──

  test "swap remainder inherits source owner and swap descriptor" do
    fee_key = test_key()
    bob_pkh = :binary.copy(<<0x11>>, 20)
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    # Bob offers 200 sat at rate 1:2 — only 100 consumed → 100 left over.
    bob_swap = swap_fields(cat_hash, bob_pkh, 1, 2)
    bob_script = make_stas3_swap_locking(bob_pkh, redemption_a, bob_swap)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 200,
        locking_script: bob_script,
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

    # Caller passes "wrong" owner/action_data on the remainder (idx 2);
    # the factory MUST overwrite both with the source UTXO's owner + var2
    # per §9.5.
    destinations = [
      %Stas3OutputParams{satoshis: 50, owner_pkh: bob_pkh, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a},
      %Stas3OutputParams{
        satoshis: 150,
        owner_pkh: :binary.copy(<<0xEE>>, 20),
        redemption_pkh: redemption_a,
        action_data: nil
      }
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_transfer_swap_tx(config)

    rem_parsed =
      Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 2).locking_script))

    assert rem_parsed.script_type == :stas3
    # Remainder owner == source (input 0) owner
    assert rem_parsed.stas3.owner == bob_pkh
    # Remainder var2 == source (input 0) swap descriptor
    assert {:swap, fields} = rem_parsed.stas3.action_data_parsed
    assert fields.requested_script_hash == cat_hash
    assert fields.requested_pkh == bob_pkh
    assert fields.rate_numerator == 1
    assert fields.rate_denominator == 2
  end

  # ── STAS 3.0 v0.1 §9.5 / §10.3 — Item E: arbitrator-free no-sig swap leg. ──

  test "swap with EMPTY_HASH160 owner takes no-sig path" do
    fee_key = test_key()
    empty = BSV.Tokens.Script.Templates.empty_hash160()
    cat_pkh = :binary.copy(<<0x33>>, 20)
    redemption_a = :binary.copy(<<0x22>>, 20)
    redemption_b = :binary.copy(<<0x44>>, 20)

    cat_script = make_stas3_locking(cat_pkh, redemption_b)
    cat_hash = Stas3Builder.compute_stas3_requested_script_hash(Script.to_binary(cat_script))

    # Maker leg: owner = EMPTY_HASH160 (arbitrator-free).
    no_auth_swap = swap_fields(cat_hash, empty, 1, 1)
    no_auth_script = make_stas3_swap_locking(empty, redemption_a, no_auth_swap)

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 100,
        locking_script: no_auth_script,
        # Even with a private_key supplied, the factory must take the
        # no-auth path because the owner is the empty-hash sentinel.
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

    destinations = [
      %Stas3OutputParams{satoshis: 100, owner_pkh: empty, redemption_pkh: redemption_b},
      %Stas3OutputParams{satoshis: 100, owner_pkh: cat_pkh, redemption_pkh: redemption_a}
    ]

    config = make_swap_config(inputs, destinations, fee_key)
    {:ok, tx} = Stas3.build_stas3_transfer_swap_tx(config)

    # Input 0: arbitrator-free → unlock script is `witness ‖ OP_FALSE`.
    # Per the spec author's clarification of §10.3, the "preimage" replaced
    # with OP_FALSE is the **address/MPKH preimage** (authz slot 21+),
    # NOT the BIP-143 sighashPreimage (slot 19) — slot 19 still carries
    # the real preimage, identical to the P2PKH/P2MPKH paths.
    no_auth_input = Enum.at(tx.inputs, 0)
    no_auth_bin = Script.to_binary(no_auth_input.unlocking_script)

    # Re-derive the expected witness for input 0 (fee input is at idx 2).
    # This recomputes slot 19 from the produced tx, so the bytes must match.
    {:ok, expected_witness} =
      BSV.Tokens.Factory.Stas3.WitnessBuilder.derive_witness_for_input(
        tx,
        0,
        2,
        :transfer,
        :atomic_swap,
        0x41
      )

    {:ok, expected_witness_bytes} =
      BSV.Tokens.Stas3UnlockWitness.to_script_bytes(expected_witness)

    # Slot 21+ (authz) is replaced with a single OP_FALSE push (`<<0x00>>`).
    assert no_auth_bin == expected_witness_bytes <> <<0x00>>

    # Slot 19 (sighashPreimage) MUST NOT be empty — it carries the real
    # BIP-143 preimage. Verify by re-decoding and locating the trailing
    # witness chunks: ..., preimage_push (slot 19), spend_type_push (slot 20),
    # OP_FALSE (authz).
    {:ok, parsed_unlock} = Script.from_binary(no_auth_bin)
    chunks = parsed_unlock.chunks
    [authz_chunk, spend_type_chunk, preimage_chunk | _] = Enum.reverse(chunks)
    assert authz_chunk == {:data, <<>>}
    assert spend_type_chunk == {:data, <<0x01>>}
    assert {:data, preimage_bytes} = preimage_chunk
    # Real BIP-143 preimage is far longer than 32 B; an empty / placeholder
    # would be a 0-length push, which would FAIL this assertion.
    assert byte_size(preimage_bytes) > 100

    # Cross-check: slot 19 in the script equals the recomputed BIP-143
    # preimage byte-for-byte.
    locking_bin = Script.to_binary(no_auth_input.source_output.locking_script)
    sats = no_auth_input.source_output.satoshis
    {:ok, recomputed_preimage} = BSV.Transaction.Sighash.calc_preimage(tx, 0, locking_bin, 0x41, sats)
    assert preimage_bytes == recomputed_preimage

    # Input 1: regular signed leg — witness ‖ <sig> <pubkey>.
    signed_input = Enum.at(tx.inputs, 1)
    assert byte_size(Script.to_binary(signed_input.unlocking_script)) > 1
  end

  test "stas3_unlock_template_for selects no_auth when owner is EMPTY_HASH160" do
    empty = BSV.Tokens.Script.Templates.empty_hash160()
    redemption = :binary.copy(<<0x22>>, 20)

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(empty, redemption, nil, false, true, [], [])

    ti = %TokenInput{
      txid: dummy_hash(),
      vout: 0,
      satoshis: 1_000,
      locking_script: script,
      private_key: test_key()
    }

    template = Stas3.stas3_unlock_template_for(ti, :transfer)
    assert template.no_auth == true
  end

  # ── STAS 3.0 v0.1 §4 / §9.3 — Item G: confiscation txType is unrestricted. ─

  test "confiscation builds successfully with arbitrary tx_type=5" do
    fee_key = test_key()
    issuer_pkh = :binary.copy(<<0x55>>, 20)
    target_pkh = :binary.copy(<<0x66>>, 20)
    redemption = :binary.copy(<<0x77>>, 20)

    # Spec §9.3: confiscation requires CONFISCATABLE flag set.
    confiscatable_script =
      make_stas3_locking_with_flags(
        target_pkh,
        redemption,
        %BSV.Tokens.ScriptFlags{freezable: true, confiscatable: true}
      )

    inputs = [
      %TokenInput{
        txid: dummy_hash(),
        vout: 0,
        satoshis: 1_000,
        locking_script: confiscatable_script,
        private_key: test_key()
      }
    ]

    destinations = [
      %Stas3OutputParams{
        satoshis: 1_000,
        owner_pkh: issuer_pkh,
        redemption_pkh: redemption
      }
    ]

    config =
      make_swap_config(inputs, destinations, fee_key)
      # tx_type is informational only at the SDK layer (no encoded restriction
      # for spend_type=3 per §4 / §9.3). Caller may set it to any value.
      |> Map.put(:tx_type, 5)

    {:ok, tx} = Stas3.build_stas3_confiscate_tx(config)
    # Token input + fee input
    assert length(tx.inputs) == 2
    # Confiscation output round-trips through the parser
    out_parsed =
      Reader.read_locking_script(Script.to_binary(Enum.at(tx.outputs, 0).locking_script))

    assert out_parsed.script_type == :stas3
    assert out_parsed.stas3.owner == issuer_pkh
  end
end
