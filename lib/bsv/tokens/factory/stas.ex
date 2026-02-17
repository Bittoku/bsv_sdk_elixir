defmodule BSV.Tokens.Factory.Stas do
  @moduledoc """
  STAS transaction factories.

  Pure functions that build complete, signed transactions for STAS token
  operations: issue, transfer, split, merge, and redeem.
  """

  alias BSV.{Crypto, Script, PrivateKey, PublicKey}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2PKH}
  alias BSV.Script.Address
  alias BSV.Tokens.Error
  alias BSV.Tokens.Script.StasBuilder
  alias BSV.Tokens.Template.Stas, as: StasTemplate

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

  # ---- Private helpers ----

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
end
