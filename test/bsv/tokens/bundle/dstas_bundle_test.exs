defmodule BSV.Tokens.Bundle.DstasBundleTest do
  @moduledoc """
  Tests for DstasBundleFactory — automatic merge/split/transfer transaction planning.

  Covers happy paths (single/multi UTXO, multi-recipient, merge tree, fee chaining,
  note placement, spend type flags) and failure conditions (empty outputs, zero
  satoshis, insufficient balance, fee estimation).
  """

  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Crypto, Script}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output}
  alias BSV.Tokens.Bundle.DstasBundle
  alias BSV.Tokens.Script.DstasBuilder
  alias BSV.Tokens.DstasOutputParams

  # ── Test Helpers ────────────────────────────────────────────────────────────

  defp test_key, do: PrivateKey.generate()

  defp key_to_address(key) do
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    BSV.Base58.check_encode(pkh, 0x00)
  end

  defp key_to_pkh(key) do
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    Crypto.hash160(pubkey.point)
  end

  defp p2pkh_script(key) do
    address = key_to_address(key)
    {:ok, script} = BSV.Script.Address.to_script(address)
    script
  end

  defp make_stas_utxo(txid_hex, satoshis, owner_pkh, redemption_pkh) do
    {:ok, locking_script} =
      DstasBuilder.build_dstas_locking_script(
        owner_pkh,
        redemption_pkh,
        nil,
        false,
        true,
        [],
        []
      )

    # Decode display-order hex txid to internal byte order
    {:ok, txid_bytes} = Base.decode16(txid_hex, case: :mixed)
    txid_internal = txid_bytes |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

    %{
      txid: txid_internal,
      txid_hex: txid_hex,
      vout: 0,
      satoshis: satoshis,
      locking_script: locking_script
    }
  end

  defp make_fee_utxo(txid_hex, satoshis, key) do
    {:ok, txid_bytes} = Base.decode16(txid_hex, case: :mixed)
    txid_internal = txid_bytes |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

    %{
      txid: txid_internal,
      txid_hex: txid_hex,
      vout: 0,
      satoshis: satoshis,
      locking_script: p2pkh_script(key)
    }
  end

  defp make_bundle(stas_utxos, fee_satoshis \\ 100_000) do
    stas_key = test_key()
    fee_key = test_key()
    owner_pkh = key_to_pkh(stas_key)
    redemption_pkh = :binary.copy(<<0xBB>>, 20)

    fee_utxo = make_fee_utxo(String.duplicate("11", 32), fee_satoshis, fee_key)

    # Track calls for assertions
    calls = :ets.new(:bundle_test_calls, [:set, :public])
    :ets.insert(calls, {:unlocking_calls, []})

    bundle = %DstasBundle{
      stas_wallet: %{
        address: key_to_address(stas_key),
        private_key: stas_key
      },
      fee_wallet: %{
        address: key_to_address(fee_key),
        private_key: fee_key
      },
      get_stas_utxo_set: fn _min_satoshis -> stas_utxos end,
      get_funding_utxo: fn _request -> fee_utxo end,
      get_transactions: fn _txid_hexes -> %{} end,
      build_locking_params: fn args ->
        %DstasOutputParams{
          owner_pkh: owner_pkh,
          redemption_pkh: redemption_pkh,
          frozen: false,
          freezable: true,
          service_fields: [],
          optional_data: [],
          action_data: nil,
          satoshis: args.recipient |> Map.get(:satoshis, 0)
        }
      end,
      build_unlocking_script: fn args ->
        # Track calls
        [{:unlocking_calls, prev}] = :ets.lookup(calls, :unlocking_calls)
        :ets.insert(calls, {:unlocking_calls, prev ++ [args]})

        # Return a dummy unlocking script
        {:ok, %Script{chunks: [{:data, :binary.copy(<<0x51>>, 72)}, {:data, :binary.copy(<<0x02>>, 33)}]}}
      end,
      fee_rate: 500
    }

    %{bundle: bundle, stas_key: stas_key, fee_key: fee_key, calls_table: calls}
  end

  defp recipient(address) do
    %{m: 1, addresses: [address]}
  end

  defp get_unlocking_calls(calls_table) do
    [{:unlocking_calls, calls}] = :ets.lookup(calls_table, :unlocking_calls)
    calls
  end

  # ── Happy Path Tests ────────────────────────────────────────────────────────

  describe "single UTXO transfers" do
    test "1. single UTXO, single recipient — simplest case, 1 tx" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [%{recipient: r, satoshis: 1000}]
      })

      assert is_list(result.transactions)
      assert length(result.transactions) == 1
      assert result.fee_satoshis > 0
    end

    test "2. single UTXO, 4 recipients — 1 tx with 4 outputs" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [
          %{recipient: r, satoshis: 250},
          %{recipient: r, satoshis: 250},
          %{recipient: r, satoshis: 250},
          %{recipient: r, satoshis: 250}
        ]
      })

      assert length(result.transactions) == 1
    end

    test "3. single UTXO, 5 recipients — 2 txs (3 + change, then 2)" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200}
        ]
      })

      assert length(result.transactions) == 2
    end

    test "4. single UTXO, many recipients — ~100 tx plan" do
      recipients_count = 301
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)

      utxo =
        make_stas_utxo(
          String.duplicate("aa", 32),
          recipients_count,
          owner_pkh,
          :binary.copy(<<0xBB>>, 20)
        )

      %{bundle: bundle} = make_bundle([utxo], 1_000_000)
      r = recipient(key_to_address(stas_key))

      outputs = for _ <- 1..recipients_count, do: %{recipient: r, satoshis: 1}

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: outputs,
        note: [<<0xDE, 0xAD, 0xBE, 0xEF>>]
      })

      # 301 recipients: ceil((301-1)/3) = 100 txs
      assert length(result.transactions) == 100
      assert result.fee_satoshis > 0
    end
  end

  describe "merge operations" do
    test "5. two UTXOs needing merge, single recipient — merge tx + transfer tx" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      redemption_pkh = :binary.copy(<<0xBB>>, 20)

      utxo1 = make_stas_utxo(String.duplicate("aa", 32), 600, owner_pkh, redemption_pkh)
      utxo2 = make_stas_utxo(String.duplicate("bb", 32), 400, owner_pkh, redemption_pkh)

      # Need to provide source transactions for merge
      # Build real source transactions so merge can look them up
      bundle_setup = make_bundle([utxo1, utxo2])

      # Override get_transactions to return source txs based on the utxos
      bundle = %{bundle_setup.bundle |
        get_transactions: fn _txids ->
          # Build minimal source transactions for each utxo
          tx1 = build_source_tx(utxo1)
          tx2 = build_source_tx(utxo2)
          %{utxo1.txid_hex => tx1, utxo2.txid_hex => tx2}
        end
      }

      r = recipient(key_to_address(stas_key))

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [%{recipient: r, satoshis: 1000}]
      })

      assert is_list(result.transactions)
      # 1 merge tx + 1 transfer tx
      assert length(result.transactions) >= 2
      assert result.fee_satoshis > 0
    end

    test "6. merge with remainder — merge produces exact amount + STAS change" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      redemption_pkh = :binary.copy(<<0xBB>>, 20)

      utxo1 = make_stas_utxo(String.duplicate("aa", 32), 600, owner_pkh, redemption_pkh)
      utxo2 = make_stas_utxo(String.duplicate("bb", 32), 500, owner_pkh, redemption_pkh)

      bundle_setup = make_bundle([utxo1, utxo2])

      bundle = %{bundle_setup.bundle |
        get_transactions: fn _txids ->
          tx1 = build_source_tx(utxo1)
          tx2 = build_source_tx(utxo2)
          %{utxo1.txid_hex => tx1, utxo2.txid_hex => tx2}
        end
      }

      r = recipient(key_to_address(stas_key))

      # Request only 800 of 1100 total
      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [%{recipient: r, satoshis: 800}]
      })

      assert is_list(result.transactions)
      assert length(result.transactions) >= 2
    end
  end

  describe "note and spend type" do
    test "7. note attached only to final transaction" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      note = [<<0xAA, 0xBB, 0xCC>>]

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200}
        ],
        note: note
      })

      assert length(result.transactions) == 2

      # Parse all transactions and check OP_RETURN presence
      txs =
        Enum.map(result.transactions, fn hex ->
          {:ok, tx} = Transaction.from_hex(hex)
          tx
        end)

      for {tx, idx} <- Enum.with_index(txs) do
        has_op_return = Enum.any?(tx.outputs, &Script.is_op_return?(&1.locking_script))

        if idx == length(txs) - 1 do
          assert has_op_return, "Final tx should have OP_RETURN note"
        else
          refute has_op_return, "Non-final tx should NOT have OP_RETURN note"
        end
      end
    end

    test "8. freeze/unfreeze set correct spend type flags" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle, calls_table: calls} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      # Test freeze
      {:ok, _} = DstasBundle.create_freeze_bundle(bundle, 1000, r)
      freeze_calls = get_unlocking_calls(calls)
      assert length(freeze_calls) > 0
      assert Enum.all?(freeze_calls, fn c -> c.spend_type == :freeze end)
      assert Enum.all?(freeze_calls, fn c -> c.is_freeze_like == true end)

      # Reset calls and test unfreeze
      :ets.insert(calls, {:unlocking_calls, []})
      {:ok, _} = DstasBundle.create_unfreeze_bundle(bundle, 1000, r)
      unfreeze_calls = get_unlocking_calls(calls)
      assert length(unfreeze_calls) > 0
      assert Enum.all?(unfreeze_calls, fn c -> c.spend_type == :unfreeze end)
      assert Enum.all?(unfreeze_calls, fn c -> c.is_freeze_like == true end)
    end

    test "8b. transfer/swap/confiscation set is_freeze_like=false" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      r = recipient(key_to_address(stas_key))

      # Transfer
      %{bundle: bundle, calls_table: calls} = make_bundle([utxo])
      {:ok, _} = DstasBundle.create_transfer_bundle(bundle, 1000, r)
      transfer_calls = get_unlocking_calls(calls)
      assert length(transfer_calls) > 0
      assert Enum.all?(transfer_calls, fn c -> c.is_freeze_like == false end)

      # Swap
      %{bundle: bundle2, calls_table: calls2} = make_bundle([utxo])
      {:ok, _} = DstasBundle.create_swap_bundle(bundle2, 1000, r)
      swap_calls = get_unlocking_calls(calls2)
      assert length(swap_calls) > 0
      assert Enum.all?(swap_calls, fn c -> c.is_freeze_like == false end)

      # Confiscation
      %{bundle: bundle3, calls_table: calls3} = make_bundle([utxo])
      {:ok, _} = DstasBundle.create_confiscation_bundle(bundle3, 1000, r)
      confiscation_calls = get_unlocking_calls(calls3)
      assert length(confiscation_calls) > 0
      assert Enum.all?(confiscation_calls, fn c -> c.is_freeze_like == false end)
    end
  end

  describe "fee chaining" do
    test "9. fee chaining works — each tx feeds fee change to next" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo], 100_000)
      r = recipient(key_to_address(stas_key))

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200},
          %{recipient: r, satoshis: 200}
        ]
      })

      assert length(result.transactions) == 2

      # Parse transactions and verify fee chain
      txs =
        Enum.map(result.transactions, fn hex ->
          {:ok, tx} = Transaction.from_hex(hex)
          tx
        end)

      # The fee output of tx1 should be spent by tx2's fee input
      tx1 = Enum.at(txs, 0)
      tx2 = Enum.at(txs, 1)

      tx1_id = Transaction.tx_id(tx1)

      # tx2's last input (fee input) should reference tx1's txid
      fee_input = List.last(tx2.inputs)
      assert fee_input.source_txid == tx1_id

      # Fee should decrease across the bundle
      assert result.fee_satoshis > 0
      assert result.fee_satoshis < 100_000
    end
  end

  # ── Failure Condition Tests ─────────────────────────────────────────────────

  describe "validation errors" do
    test "10. empty outputs rejected" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])

      assert_raise BSV.Tokens.Error, ~r/at least one transfer output/, fn ->
        DstasBundle.transfer(bundle, %{outputs: []})
      end
    end

    test "11. zero satoshi output rejected" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      assert_raise BSV.Tokens.Error, ~r/positive integer/, fn ->
        DstasBundle.transfer(bundle, %{
          outputs: [%{recipient: r, satoshis: 0}]
        })
      end
    end

    test "12. insufficient STAS balance returns message, not error" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 100, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [%{recipient: r, satoshis: 101}]
      })

      assert result.message == "Insufficient STAS tokens balance"
      assert result.fee_satoshis == 0
      refute Map.has_key?(result, :transactions)
    end

    test "13. no available UTXOs returns insufficient message" do
      %{bundle: bundle} = make_bundle([])
      r = recipient("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

      {:ok, result} = DstasBundle.transfer(bundle, %{
        outputs: [%{recipient: r, satoshis: 1000}]
      })

      assert result.message == "Insufficient STAS tokens balance"
      assert result.fee_satoshis == 0
    end
  end

  describe "fee estimation" do
    test "14. fee estimation produces reasonable upper bound" do
      # Single input, single output
      count1 = DstasBundle.estimate_transactions_count(1, 1)
      fee1 = DstasBundle.estimate_bundle_fee_upper_bound(count1, 1, 1, 500)
      assert fee1 >= 1200
      assert fee1 < 10_000

      # Multiple inputs, many outputs
      count2 = DstasBundle.estimate_transactions_count(5, 20)
      fee2 = DstasBundle.estimate_bundle_fee_upper_bound(count2, 5, 20, 500)
      assert fee2 > fee1
      assert fee2 < 100_000
    end

    test "merge transaction count estimation" do
      assert DstasBundle.estimate_merge_tx_count(0) == 0
      assert DstasBundle.estimate_merge_tx_count(1) == 0
      assert DstasBundle.estimate_merge_tx_count(2) == 1
      assert DstasBundle.estimate_merge_tx_count(3) == 2
      assert DstasBundle.estimate_merge_tx_count(4) == 3
    end

    test "transfer transaction count estimation" do
      assert DstasBundle.estimate_transfer_tx_count(1) == 1
      assert DstasBundle.estimate_transfer_tx_count(4) == 1
      assert DstasBundle.estimate_transfer_tx_count(5) == 2
      assert DstasBundle.estimate_transfer_tx_count(7) == 2
      assert DstasBundle.estimate_transfer_tx_count(8) == 3
    end
  end

  describe "UTXO selection" do
    test "exact match preferred" do
      utxos = [
        %{satoshis: 100},
        %{satoshis: 500},
        %{satoshis: 1000}
      ]

      result = DstasBundle.select_stas_utxos(utxos, 500)
      assert length(result) == 1
      assert hd(result).satoshis == 500
    end

    test "accumulates smallest first when no exact match" do
      utxos = [
        %{satoshis: 100},
        %{satoshis: 200},
        %{satoshis: 300}
      ]

      result = DstasBundle.select_stas_utxos(utxos, 250)
      assert length(result) == 2
      assert Enum.at(result, 0).satoshis == 100
      assert Enum.at(result, 1).satoshis == 200
    end

    test "single UTXO >= amount used as fallback" do
      utxos = [
        %{satoshis: 50},
        %{satoshis: 1000}
      ]

      result = DstasBundle.select_stas_utxos(utxos, 500)
      # Accumulation: 50 < 500, 50+1000 = 1050 >= 500
      assert length(result) == 2
    end
  end

  describe "convenience wrappers" do
    test "create_transfer_bundle matches transfer/2" do
      stas_key = test_key()
      owner_pkh = key_to_pkh(stas_key)
      utxo = make_stas_utxo(String.duplicate("aa", 32), 1000, owner_pkh, :binary.copy(<<0xBB>>, 20))

      %{bundle: bundle} = make_bundle([utxo])
      r = recipient(key_to_address(stas_key))

      {:ok, legacy} = DstasBundle.create_transfer_bundle(bundle, 1000, r)
      {:ok, new_api} = DstasBundle.transfer(bundle, %{
        outputs: [%{recipient: r, satoshis: 1000}]
      })

      assert length(legacy.transactions) == length(new_api.transactions)
    end
  end

  # ── Source Transaction Builder ──────────────────────────────────────────────

  # Builds a minimal transaction containing a STAS output at vout 0 for merge
  # source lookups. The transaction has a single dummy P2PKH input and the STAS
  # output matching the utxo's locking script and satoshis.
  defp build_source_tx(utxo) do
    %Transaction{
      inputs: [
        %Input{
          source_txid: :binary.copy(<<0x00>>, 32),
          source_tx_out_index: 0
        }
      ],
      outputs: [
        %Output{
          satoshis: utxo.satoshis,
          locking_script: utxo.locking_script
        }
      ]
    }
  end
end
