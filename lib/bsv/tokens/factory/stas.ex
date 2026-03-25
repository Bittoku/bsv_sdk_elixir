defmodule BSV.Tokens.Factory.Stas do
  @moduledoc """
  STAS transaction factories.

  Pure functions that build complete, signed transactions for STAS token
  operations: issue, transfer, split, merge, redeem, freeze, unfreeze,
  confiscation, and swap.

  ## v2 Functions (Legacy)

  Functions without a `v3_` prefix use the legacy STAS v2 template (P2PKH-only,
  splittable flag). These are retained for backward compatibility.

  ## v3 Functions

  Functions prefixed with `v3_` use the new script template with full protocol
  support: P2MPKH ownership, 2nd variable field, flags (freezable/confiscatable),
  service fields, spending types, and per-transaction note outputs.
  """

  alias BSV.{Crypto, Script, PrivateKey, PublicKey}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2PKH}
  alias BSV.Script.Address
  alias BSV.Tokens.Error
  alias BSV.Tokens.Script.StasBuilder
  alias BSV.Tokens.Script.DstasBuilder
  alias BSV.Tokens.Template.Stas, as: StasTemplate
  alias BSV.Tokens.ScriptFlags

  # ---- Config types ----

  @type issue_config :: %{
          contract_utxo: BSV.Tokens.Payment.t(),
          destinations: [BSV.Tokens.Destination.t()],
          redemption_pkh: <<_::160>>,
          splittable: boolean(),
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  @type transfer_config :: %{
          token_utxo: BSV.Tokens.Payment.t(),
          destination: BSV.Tokens.Destination.t(),
          redemption_pkh: <<_::160>>,
          splittable: boolean(),
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  @type split_config :: %{
          token_utxo: BSV.Tokens.Payment.t(),
          destinations: [BSV.Tokens.Destination.t()],
          redemption_pkh: <<_::160>>,
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  @type merge_config :: %{
          token_utxos: [BSV.Tokens.Payment.t()],
          destination: BSV.Tokens.Destination.t(),
          redemption_pkh: <<_::160>>,
          splittable: boolean(),
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  @type redeem_config :: %{
          token_utxo: BSV.Tokens.Payment.t(),
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  # ---- Helpers ----

  defp make_input(payment) do
    %Input{
      source_txid: payment.txid,
      source_tx_out_index: payment.vout,
      source_output: %Output{
        satoshis: payment.satoshis,
        locking_script: payment.locking_script
      }
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

  defp add_change_output(tx, funding, fee_rate) do
    est_size = estimate_size(length(tx.inputs), tx.outputs) + 34
    fee = div(est_size * fee_rate + 999, 1000)

    if funding.satoshis < fee do
      {:error, Error.insufficient_funds(fee, funding.satoshis)}
    else
      change = funding.satoshis - fee

      tx =
        if change > 0 do
          addr = change_address(funding.private_key)
          {:ok, change_script} = Address.to_script(addr)
          change_out = %Output{satoshis: change, locking_script: change_script, change: true}
          %{tx | outputs: tx.outputs ++ [change_out]}
        else
          tx
        end

      {:ok, tx}
    end
  end

  defp sign_stas_input(tx, index, private_key) do
    template = StasTemplate.unlock(private_key)
    StasTemplate.sign(template, tx, index)
  end

  defp sign_p2pkh_input(tx, index, private_key) do
    template = P2PKH.unlock(private_key)
    P2PKH.sign(template, tx, index)
  end

  defp set_unlocking_script(tx, index, script) do
    inputs =
      List.update_at(tx.inputs, index, fn inp ->
        %{inp | unlocking_script: script}
      end)

    %{tx | inputs: inputs}
  end

  defp resolve_owner_pkh(address_string) do
    case BSV.Base58.check_decode(address_string) do
      {:ok, {_version, <<pkh::binary-size(20)>>}} -> {:ok, pkh}
      _ -> {:error, Error.invalid_destination("cannot decode address: #{address_string}")}
    end
  end

  # ---- Factory functions ----

  @doc "Build an issue transaction."
  @spec build_issue_tx(issue_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_issue_tx(config) do
    cond do
      config.destinations == [] ->
        {:error, Error.invalid_destination("at least one destination required")}

      true ->
        total_tokens = Enum.sum(Enum.map(config.destinations, & &1.satoshis))

        if total_tokens != config.contract_utxo.satoshis do
          {:error, Error.amount_mismatch(config.contract_utxo.satoshis, total_tokens)}
        else
          with {:ok, token_outputs} <- build_stas_outputs(config.destinations, config.redemption_pkh, config.splittable) do
            tx = %Transaction{
              inputs: [make_input(config.contract_utxo), make_input(config.funding)],
              outputs: token_outputs
            }

            with {:ok, tx} <- add_change_output(tx, config.funding, config.fee_rate),
                 {:ok, sig0} <- sign_p2pkh_input(tx, 0, config.contract_utxo.private_key),
                 {:ok, sig1} <- sign_p2pkh_input(tx, 1, config.funding.private_key) do
              tx = tx |> set_unlocking_script(0, sig0) |> set_unlocking_script(1, sig1)
              {:ok, tx}
            end
          end
        end
    end
  end

  @doc "Build a transfer transaction."
  @spec build_transfer_tx(transfer_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_transfer_tx(config) do
    if config.destination.satoshis != config.token_utxo.satoshis do
      {:error, Error.amount_mismatch(config.token_utxo.satoshis, config.destination.satoshis)}
    else
      with {:ok, owner_pkh} <- resolve_owner_pkh(config.destination.address),
           {:ok, locking_script} <-
             StasBuilder.build_stas_locking_script(
               owner_pkh,
               config.redemption_pkh,
               config.splittable
             ) do
        token_output = %Output{satoshis: config.destination.satoshis, locking_script: locking_script}

        tx = %Transaction{
          inputs: [make_input(config.token_utxo), make_input(config.funding)],
          outputs: [token_output]
        }

        with {:ok, tx} <- add_change_output(tx, config.funding, config.fee_rate),
             {:ok, sig0} <- sign_stas_input(tx, 0, config.token_utxo.private_key),
             {:ok, sig1} <- sign_p2pkh_input(tx, 1, config.funding.private_key) do
          tx = tx |> set_unlocking_script(0, sig0) |> set_unlocking_script(1, sig1)
          {:ok, tx}
        end
      end
    end
  end

  @doc "Build a split transaction."
  @spec build_split_tx(split_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_split_tx(config) do
    cond do
      config.destinations == [] ->
        {:error, Error.invalid_destination("at least one destination required")}

      length(config.destinations) > 4 ->
        {:error, Error.invalid_destination("maximum 4 split destinations allowed")}

      true ->
        total = Enum.sum(Enum.map(config.destinations, & &1.satoshis))

        if total != config.token_utxo.satoshis do
          {:error, Error.amount_mismatch(config.token_utxo.satoshis, total)}
        else
          with {:ok, token_outputs} <- build_stas_outputs(config.destinations, config.redemption_pkh, true) do
            tx = %Transaction{
              inputs: [make_input(config.token_utxo), make_input(config.funding)],
              outputs: token_outputs
            }

            with {:ok, tx} <- add_change_output(tx, config.funding, config.fee_rate),
                 {:ok, sig0} <- sign_stas_input(tx, 0, config.token_utxo.private_key),
                 {:ok, sig1} <- sign_p2pkh_input(tx, 1, config.funding.private_key) do
              tx = tx |> set_unlocking_script(0, sig0) |> set_unlocking_script(1, sig1)
              {:ok, tx}
            end
          end
        end
    end
  end

  @doc "Build a merge transaction."
  @spec build_merge_tx(merge_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_merge_tx(config) do
    cond do
      length(config.token_utxos) < 2 ->
        {:error, Error.invalid_destination("at least 2 token UTXOs required for merge")}

      true ->
        total_tokens = Enum.sum(Enum.map(config.token_utxos, & &1.satoshis))

        if total_tokens != config.destination.satoshis do
          {:error, Error.amount_mismatch(total_tokens, config.destination.satoshis)}
        else
          with {:ok, owner_pkh} <- resolve_owner_pkh(config.destination.address),
               {:ok, locking_script} <-
                 StasBuilder.build_stas_locking_script(
                   owner_pkh,
                   config.redemption_pkh,
                   config.splittable
                 ) do
            token_output = %Output{satoshis: config.destination.satoshis, locking_script: locking_script}
            token_inputs = Enum.map(config.token_utxos, &make_input/1)

            tx = %Transaction{
              inputs: token_inputs ++ [make_input(config.funding)],
              outputs: [token_output]
            }

            with {:ok, tx} <- add_change_output(tx, config.funding, config.fee_rate) do
              funding_index = length(config.token_utxos)

              # Sign token inputs
              result =
                Enum.reduce_while(0..(length(config.token_utxos) - 1), {:ok, tx}, fn i, {:ok, tx} ->
                  utxo = Enum.at(config.token_utxos, i)

                  case sign_stas_input(tx, i, utxo.private_key) do
                    {:ok, sig} -> {:cont, {:ok, set_unlocking_script(tx, i, sig)}}
                    error -> {:halt, error}
                  end
                end)

              with {:ok, tx} <- result,
                   {:ok, fund_sig} <- sign_p2pkh_input(tx, funding_index, config.funding.private_key) do
                {:ok, set_unlocking_script(tx, funding_index, fund_sig)}
              end
            end
          end
        end
    end
  end

  @doc "Build a redeem (burn) transaction."
  @spec build_redeem_tx(redeem_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_redeem_tx(config) do
    op_return_output = %Output{satoshis: 0, locking_script: Script.op_return([])}

    tx = %Transaction{
      inputs: [make_input(config.token_utxo), make_input(config.funding)],
      outputs: [op_return_output]
    }

    # Estimate fee for redeem (token sats + funding - fee → change)
    est_size = estimate_size(2, tx.outputs) + 34
    fee = div(est_size * config.fee_rate + 999, 1000)

    total_in = config.token_utxo.satoshis + config.funding.satoshis

    if total_in < fee do
      {:error, Error.insufficient_funds(fee, total_in)}
    else
      change = total_in - fee

      tx =
        if change > 0 do
          addr = change_address(config.funding.private_key)
          {:ok, change_script} = Address.to_script(addr)
          change_out = %Output{satoshis: change, locking_script: change_script, change: true}
          %{tx | outputs: tx.outputs ++ [change_out]}
        else
          tx
        end

      with {:ok, sig0} <- sign_stas_input(tx, 0, config.token_utxo.private_key),
           {:ok, sig1} <- sign_p2pkh_input(tx, 1, config.funding.private_key) do
        tx = tx |> set_unlocking_script(0, sig0) |> set_unlocking_script(1, sig1)
        {:ok, tx}
      end
    end
  end

  # ---- Private helpers (v2) ----

  defp build_stas_outputs(destinations, redemption_pkh, splittable) do
    Enum.reduce_while(destinations, {:ok, []}, fn dest, {:ok, acc} ->
      with {:ok, owner_pkh} <- resolve_owner_pkh(dest.address),
           {:ok, script} <-
             StasBuilder.build_stas_locking_script(owner_pkh, redemption_pkh, splittable) do
        output = %Output{satoshis: dest.satoshis, locking_script: script}
        {:cont, {:ok, acc ++ [output]}}
      else
        error -> {:halt, error}
      end
    end)
  end

  # ===========================================================================
  # V3 Factory Functions
  # ===========================================================================

  @typedoc """
  Output parameters for v3 STAS operations.

  Same structure as `DstasOutputParams` — these are protocol-level fields, not
  dSTAS-specific.
  """
  @type v3_output_params :: %{
          satoshis: non_neg_integer(),
          owner_pkh: <<_::160>>,
          redemption_pkh: <<_::160>>,
          frozen: boolean(),
          flags: ScriptFlags.t(),
          service_fields: [binary()],
          optional_data: [binary()],
          action_data: BSV.Tokens.ActionData.t() | nil
        }

  @typedoc "Config for v3 base spend operations."
  @type v3_base_config :: %{
          token_inputs: [BSV.Tokens.TokenInput.t()],
          fee_txid: binary(),
          fee_vout: non_neg_integer(),
          fee_satoshis: non_neg_integer(),
          fee_locking_script: Script.t(),
          fee_private_key: PrivateKey.t(),
          destinations: [v3_output_params()],
          spend_type: BSV.Tokens.SpendType.t(),
          fee_rate: non_neg_integer(),
          note_data: binary() | nil
        }

  @doc """
  Build a v3 STAS base transaction.

  This is the core v3 transaction builder. All v3 operations (transfer, split,
  merge, freeze, unfreeze, confiscation, swap) route through this function with
  appropriate `spend_type` and destination parameters.

  Supports 1–2 token inputs, 1–4 STAS outputs, optional note output, and a
  fee change output.
  """
  @spec build_v3_base_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_base_tx(config) do
    cond do
      config.destinations == [] ->
        {:error, Error.invalid_destination("at least one destination required")}

      config.token_inputs == [] or length(config.token_inputs) > 2 ->
        {:error, Error.invalid_destination("v3 base tx requires 1 or 2 token inputs")}

      true ->
        total_in = Enum.sum(Enum.map(config.token_inputs, & &1.satoshis))
        total_out = Enum.sum(Enum.map(config.destinations, & &1.satoshis))

        if total_in != total_out do
          {:error, Error.amount_mismatch(total_in, total_out)}
        else
          token_inputs =
            Enum.map(config.token_inputs, fn ti ->
              make_input(%{txid: ti.txid, vout: ti.vout, satoshis: ti.satoshis, locking_script: ti.locking_script})
            end)

          fee_input =
            make_input(%{
              txid: config.fee_txid,
              vout: config.fee_vout,
              satoshis: config.fee_satoshis,
              locking_script: config.fee_locking_script
            })

          with {:ok, stas_outputs} <- build_v3_outputs(config.destinations) do
            # Add optional note output
            outputs =
              case Map.get(config, :note_data) do
                nil -> stas_outputs
                <<>> -> stas_outputs
                data when is_binary(data) ->
                  note_script = Script.op_return([data])
                  stas_outputs ++ [%Output{satoshis: 0, locking_script: note_script}]
              end

            tx = %Transaction{
              inputs: token_inputs ++ [fee_input],
              outputs: outputs
            }

            with {:ok, tx} <- add_change_output_v3(tx, config.fee_satoshis, config.fee_private_key, config.fee_rate) do
              # Sign token inputs
              result =
                Enum.reduce_while(
                  0..(length(config.token_inputs) - 1),
                  {:ok, tx},
                  fn i, {:ok, tx} ->
                    ti = Enum.at(config.token_inputs, i)
                    template = StasTemplate.unlock(ti.private_key, spend_type: config.spend_type)

                    case StasTemplate.sign(template, tx, i) do
                      {:ok, sig} -> {:cont, {:ok, set_unlocking_script(tx, i, sig)}}
                      error -> {:halt, error}
                    end
                  end
                )

              with {:ok, tx} <- result do
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

  @doc "Build a v3 STAS transfer transaction (spending type 1)."
  @spec build_v3_transfer_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_transfer_tx(config) do
    build_v3_base_tx(%{config | spend_type: :transfer})
  end

  @doc """
  Build a v3 STAS split transaction.

  Exactly 1 token input, 1–4 outputs. Spending type 1.
  """
  @spec build_v3_split_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_split_tx(config) do
    cond do
      length(config.token_inputs) != 1 ->
        {:error, Error.invalid_destination("split requires exactly 1 STAS input")}

      length(config.destinations) < 1 or length(config.destinations) > 4 ->
        {:error, Error.invalid_destination("split requires 1-4 destinations")}

      true ->
        build_v3_base_tx(%{config | spend_type: :transfer})
    end
  end

  @doc """
  Build a v3 STAS merge transaction.

  Exactly 2 token inputs, 1–2 outputs. Spending type 1.
  """
  @spec build_v3_merge_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_merge_tx(config) do
    cond do
      length(config.token_inputs) != 2 ->
        {:error, Error.invalid_destination("merge requires exactly 2 STAS inputs")}

      length(config.destinations) < 1 or length(config.destinations) > 2 ->
        {:error, Error.invalid_destination("merge requires 1-2 destinations")}

      true ->
        build_v3_base_tx(%{config | spend_type: :transfer})
    end
  end

  @doc """
  Build a v3 STAS freeze transaction.

  Sets frozen=true on all destinations. Spending type 2.
  Requires the token to have the freezable flag set at issuance.
  """
  @spec build_v3_freeze_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_freeze_tx(config) do
    frozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: true} end)
    build_v3_base_tx(%{config | spend_type: :freeze_unfreeze, destinations: frozen_dests})
  end

  @doc """
  Build a v3 STAS unfreeze transaction.

  Sets frozen=false on all destinations. Spending type 2.
  """
  @spec build_v3_unfreeze_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_unfreeze_tx(config) do
    unfrozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: false} end)
    build_v3_base_tx(%{config | spend_type: :freeze_unfreeze, destinations: unfrozen_dests})
  end

  @doc """
  Build a v3 STAS confiscation transaction.

  Spending type 3. No restrictions on output address, 2nd variable field, or
  number of outputs. Authorized by the confiscation authority address.
  Works on frozen and swap-configured UTXOs.
  """
  @spec build_v3_confiscate_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_confiscate_tx(config) do
    build_v3_base_tx(%{config | spend_type: :confiscation})
  end

  @doc """
  Build a v3 STAS swap cancellation transaction.

  Spending type 4. Cancels a standing swap offer by spending the UTXO back
  to the maker's receive address.
  """
  @spec build_v3_swap_cancel_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_swap_cancel_tx(config) do
    build_v3_base_tx(%{config | spend_type: :swap_cancellation})
  end

  @doc """
  Build a v3 STAS swap transaction.

  Requires exactly 2 token inputs. Spending type 1 for transfer-swap,
  spending type 4 for swap-swap. Auto-detects based on input scripts.
  """
  @spec build_v3_swap_flow_tx(v3_base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_v3_swap_flow_tx(config) do
    cond do
      length(config.token_inputs) != 2 ->
        {:error, Error.invalid_destination("swap flow requires exactly 2 token inputs")}

      length(config.destinations) < 2 or length(config.destinations) > 4 ->
        {:error, Error.invalid_destination("swap requires 2-4 destinations")}

      true ->
        # Check if any inputs are frozen
        frozen =
          Enum.any?(config.token_inputs, fn ti ->
            parsed =
              BSV.Tokens.Script.Reader.read_locking_script(Script.to_binary(ti.locking_script))

            (parsed.script_type == :dstas and parsed.dstas != nil and parsed.dstas.frozen) or
              (parsed.script_type == :stas and parsed.stas != nil and Map.get(parsed.stas, :frozen, false))
          end)

        if frozen do
          {:error, Error.invalid_destination("frozen inputs cannot be swapped")}
        else
          # Detect swap mode
          swap_count =
            Enum.count(config.token_inputs, fn ti ->
              parsed =
                BSV.Tokens.Script.Reader.read_locking_script(Script.to_binary(ti.locking_script))

              cond do
                parsed.script_type == :dstas and parsed.dstas != nil ->
                  match?({:swap, %{}}, parsed.dstas.action_data_parsed)

                true ->
                  false
              end
            end)

          spend_type = if swap_count == 2, do: :swap_cancellation, else: :transfer
          build_v3_base_tx(%{config | spend_type: spend_type})
        end
    end
  end

  # ---- Private helpers (v3) ----

  defp build_v3_outputs(destinations) do
    Enum.reduce_while(destinations, {:ok, []}, fn dest, {:ok, acc} ->
      flags = Map.get(dest, :flags, %ScriptFlags{})
      service_fields = Map.get(dest, :service_fields, [])
      optional_data = Map.get(dest, :optional_data, [])
      action_data = Map.get(dest, :action_data, nil)
      frozen = Map.get(dest, :frozen, false)

      case DstasBuilder.build_dstas_locking_script(
             dest.owner_pkh,
             dest.redemption_pkh,
             action_data,
             frozen,
             flags,
             service_fields,
             optional_data
           ) do
        {:ok, script} ->
          output = %Output{satoshis: dest.satoshis, locking_script: script}
          {:cont, {:ok, acc ++ [output]}}

        error ->
          {:halt, error}
      end
    end)
  end

  defp add_change_output_v3(tx, fee_satoshis, fee_private_key, fee_rate) do
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
end
