defmodule BSV.Tokens.Factory.Dstas do
  @moduledoc """
  DSTAS transaction factories.

  Pure functions that build complete, signed transactions for dSTAS token
  operations: two-tx issuance, base spend, freeze, unfreeze, and swap.
  """

  alias BSV.{Crypto, Script, PrivateKey, PublicKey}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2PKH}
  alias BSV.Script.Address
  alias BSV.Tokens.Error
  alias BSV.Tokens.Script.DstasBuilder
  alias BSV.Tokens.Template.Dstas, as: DstasTemplate

  # ---- Config types ----

  @type issue_config :: %{
          scheme: BSV.Tokens.Scheme.t(),
          funding_txid: binary(),
          funding_vout: non_neg_integer(),
          funding_satoshis: non_neg_integer(),
          funding_locking_script: Script.t(),
          funding_private_key: PrivateKey.t(),
          outputs: [%{satoshis: non_neg_integer(), owner_pkh: <<_::160>>, freezable: boolean()}],
          fee_rate: non_neg_integer()
        }

  @type base_config :: %{
          token_inputs: [BSV.Tokens.TokenInput.t()],
          fee_txid: binary(),
          fee_vout: non_neg_integer(),
          fee_satoshis: non_neg_integer(),
          fee_locking_script: Script.t(),
          fee_private_key: PrivateKey.t(),
          destinations: [BSV.Tokens.DstasOutputParams.t()],
          spend_type: BSV.Tokens.DstasSpendType.t(),
          fee_rate: non_neg_integer()
        }

  # ---- Helpers ----

  defp make_input(txid, vout, satoshis, locking_script) do
    %Input{
      source_txid: txid,
      source_tx_out_index: vout,
      source_output: %Output{satoshis: satoshis, locking_script: locking_script}
    }
  end

  defp estimate_size(num_inputs, outputs) do
    base = 4 + 1 + 1 + 4
    inputs_size = num_inputs * (32 + 4 + 1 + 106 + 4)

    outputs_size =
      Enum.reduce(outputs, 0, fn out, acc ->
        acc + 8 + 1 + byte_size(Script.to_binary(out.locking_script))
      end)

    base + inputs_size + outputs_size
  end

  defp change_address(private_key) do
    pubkey = PrivateKey.to_public_key(private_key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    BSV.Base58.check_encode(pkh, 0x00)
  end

  defp add_fee_change(tx, fee_satoshis, fee_private_key, fee_rate) do
    est_size = estimate_size(length(tx.inputs), tx.outputs) + 34
    fee = div(est_size * fee_rate + 999, 1000)

    if fee_satoshis < fee do
      {:error, Error.insufficient_funds(fee, fee_satoshis)}
    else
      change = fee_satoshis - fee

      tx =
        if change > 0 do
          addr = change_address(fee_private_key)
          {:ok, change_script} = Address.to_script(addr)
          change_out = %Output{satoshis: change, locking_script: change_script, change: true}
          %{tx | outputs: tx.outputs ++ [change_out]}
        else
          tx
        end

      {:ok, tx}
    end
  end

  defp set_unlocking_script(tx, index, script) do
    inputs = List.update_at(tx.inputs, index, fn inp -> %{inp | unlocking_script: script} end)
    %{tx | inputs: inputs}
  end

  # ---- Factory functions ----

  @doc "Build the two-transaction DSTAS issuance flow."
  @spec build_dstas_issue_txs(issue_config()) ::
          {:ok, %{contract_tx: Transaction.t(), issue_tx: Transaction.t()}} | {:error, term()}
  def build_dstas_issue_txs(config) do
    if config.outputs == [] do
      {:error, Error.invalid_destination("at least one output required for DSTAS issuance")}
    else
      total_tokens = Enum.sum(Enum.map(config.outputs, & &1.satoshis))

      if total_tokens == 0 do
        {:error, Error.invalid_destination("total token satoshis must be > 0")}
      else
        pubkey = PrivateKey.to_public_key(config.funding_private_key) |> PublicKey.compress()
        issuer_pkh = Crypto.hash160(pubkey.point)
        issuer_address = BSV.Base58.check_encode(issuer_pkh, 0x00)

        with {:ok, issuer_script} <- Address.to_script(issuer_address),
             {:ok, scheme_json} <- BSV.Tokens.Scheme.to_json(config.scheme) do
          # --- Contract TX ---
          fund_input =
            make_input(
              config.funding_txid,
              config.funding_vout,
              config.funding_satoshis,
              config.funding_locking_script
            )

          contract_output = %Output{satoshis: total_tokens, locking_script: issuer_script}
          op_return_output = %Output{satoshis: 0, locking_script: Script.op_return([scheme_json])}

          contract_tx = %Transaction{
            inputs: [fund_input],
            outputs: [contract_output, op_return_output]
          }

          # Estimate fee
          est_size = estimate_size(1, contract_tx.outputs) + 34
          contract_fee = div(est_size * config.fee_rate + 999, 1000)
          needed = total_tokens + contract_fee

          if config.funding_satoshis < needed do
            {:error, Error.insufficient_funds(needed, config.funding_satoshis)}
          else
            contract_change = config.funding_satoshis - total_tokens - contract_fee

            contract_tx =
              if contract_change > 0 do
                {:ok, change_script} = Address.to_script(issuer_address)

                change_out = %Output{
                  satoshis: contract_change,
                  locking_script: change_script,
                  change: true
                }

                %{contract_tx | outputs: contract_tx.outputs ++ [change_out]}
              else
                contract_tx
              end

            # Sign contract TX
            unlocker = P2PKH.unlock(config.funding_private_key)

            with {:ok, sig} <- P2PKH.sign(unlocker, contract_tx, 0) do
              contract_tx = set_unlocking_script(contract_tx, 0, sig)
              contract_txid = Transaction.tx_id(contract_tx)

              # --- Issue TX ---
              {:ok, contract_out_script} = Address.to_script(issuer_address)

              contract_input =
                make_input(contract_txid, 0, total_tokens, contract_out_script)

              issue_inputs =
                if contract_change > 0 do
                  {:ok, change_scr} = Address.to_script(issuer_address)
                  change_input = make_input(contract_txid, 2, contract_change, change_scr)
                  [contract_input, change_input]
                else
                  [contract_input]
                end

              redemption_pkh = issuer_pkh

              # Build DSTAS token outputs
              with {:ok, token_outputs} <- build_dstas_outputs(config.outputs, redemption_pkh) do
                issue_tx = %Transaction{inputs: issue_inputs, outputs: token_outputs}

                # Fee change for issue TX
                fee_available = if contract_change > 0, do: contract_change, else: 0

                issue_tx =
                  if fee_available > 0 do
                    case add_fee_change(
                           issue_tx,
                           fee_available,
                           config.funding_private_key,
                           config.fee_rate
                         ) do
                      {:ok, tx} -> tx
                      _ -> issue_tx
                    end
                  else
                    issue_tx
                  end

                # Sign all issue TX inputs (all P2PKH)
                result =
                  Enum.reduce_while(0..(length(issue_tx.inputs) - 1), {:ok, issue_tx}, fn i,
                                                                                          {:ok,
                                                                                           tx} ->
                    unlocker = P2PKH.unlock(config.funding_private_key)

                    case P2PKH.sign(unlocker, tx, i) do
                      {:ok, sig} -> {:cont, {:ok, set_unlocking_script(tx, i, sig)}}
                      error -> {:halt, error}
                    end
                  end)

                case result do
                  {:ok, issue_tx} ->
                    {:ok, %{contract_tx: contract_tx, issue_tx: issue_tx}}

                  error ->
                    error
                end
              end
            end
          end
        end
      end
    end
  end

  @doc "Build a generic DSTAS spend transaction."
  @spec build_dstas_base_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_dstas_base_tx(config) do
    cond do
      config.destinations == [] ->
        {:error, Error.invalid_destination("at least one destination required")}

      config.token_inputs == [] or length(config.token_inputs) > 2 ->
        {:error, Error.invalid_destination("DSTAS base tx requires 1 or 2 token inputs")}

      true ->
        total_in = Enum.sum(Enum.map(config.token_inputs, & &1.satoshis))
        total_out = Enum.sum(Enum.map(config.destinations, & &1.satoshis))

        if total_in != total_out do
          {:error, Error.amount_mismatch(total_in, total_out)}
        else
          token_inputs =
            Enum.map(config.token_inputs, fn ti ->
              make_input(ti.txid, ti.vout, ti.satoshis, ti.locking_script)
            end)

          fee_input =
            make_input(
              config.fee_txid,
              config.fee_vout,
              config.fee_satoshis,
              config.fee_locking_script
            )

          with {:ok, dstas_outputs} <- build_dstas_dest_outputs(config.destinations) do
            tx = %Transaction{
              inputs: token_inputs ++ [fee_input],
              outputs: dstas_outputs
            }

            with {:ok, tx} <-
                   add_fee_change(tx, config.fee_satoshis, config.fee_private_key, config.fee_rate) do
              # Sign token inputs with DSTAS template
              result =
                Enum.reduce_while(
                  0..(length(config.token_inputs) - 1),
                  {:ok, tx},
                  fn i, {:ok, tx} ->
                    ti = Enum.at(config.token_inputs, i)
                    template = DstasTemplate.unlock(ti.private_key, config.spend_type)

                    case DstasTemplate.sign(template, tx, i) do
                      {:ok, sig} -> {:cont, {:ok, set_unlocking_script(tx, i, sig)}}
                      error -> {:halt, error}
                    end
                  end
                )

              with {:ok, tx} <- result do
                # Sign fee input with P2PKH
                fee_idx = length(config.token_inputs)
                unlocker = P2PKH.unlock(config.fee_private_key)

                case P2PKH.sign(unlocker, tx, fee_idx) do
                  {:ok, sig} -> {:ok, set_unlocking_script(tx, fee_idx, sig)}
                  error -> error
                end
              end
            end
          end
        end
    end
  end

  @doc "Build a DSTAS freeze transaction."
  @spec build_dstas_freeze_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_dstas_freeze_tx(config) do
    frozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: true} end)

    build_dstas_base_tx(%{
      config
      | spend_type: :freeze_unfreeze,
        destinations: frozen_dests
    })
  end

  @doc "Build a DSTAS unfreeze transaction."
  @spec build_dstas_unfreeze_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_dstas_unfreeze_tx(config) do
    unfrozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: false} end)

    build_dstas_base_tx(%{
      config
      | spend_type: :freeze_unfreeze,
        destinations: unfrozen_dests
    })
  end

  @doc "Build a DSTAS swap flow transaction."
  @spec build_dstas_swap_flow_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_dstas_swap_flow_tx(config) do
    if length(config.token_inputs) != 2 do
      {:error, Error.invalid_destination("swap flow requires exactly 2 token inputs")}
    else
      build_dstas_base_tx(%{config | spend_type: :transfer})
    end
  end

  # ---- Private helpers ----

  defp build_dstas_outputs(outputs, redemption_pkh) do
    Enum.reduce_while(outputs, {:ok, []}, fn out, {:ok, acc} ->
      case DstasBuilder.build_dstas_locking_script(
             out.owner_pkh,
             redemption_pkh,
             nil,
             false,
             Map.get(out, :freezable, true),
             [],
             []
           ) do
        {:ok, script} ->
          output = %Output{satoshis: out.satoshis, locking_script: script}
          {:cont, {:ok, acc ++ [output]}}

        error ->
          {:halt, error}
      end
    end)
  end

  defp build_dstas_dest_outputs(destinations) do
    Enum.reduce_while(destinations, {:ok, []}, fn dest, {:ok, acc} ->
      case DstasBuilder.build_dstas_locking_script(
             dest.owner_pkh,
             dest.redemption_pkh,
             nil,
             dest.frozen,
             dest.freezable,
             dest.service_fields,
             dest.optional_data
           ) do
        {:ok, script} ->
          output = %Output{satoshis: dest.satoshis, locking_script: script}
          {:cont, {:ok, acc ++ [output]}}

        error ->
          {:halt, error}
      end
    end)
  end
end
