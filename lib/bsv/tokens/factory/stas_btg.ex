defmodule BSV.Tokens.Factory.StasBtg do
  @moduledoc """
  STAS-BTG transaction factories.

  Pure functions that build complete, signed transactions for STAS-BTG token
  operations: transfer, split, merge, and checkpoint.
  """

  alias BSV.{Crypto, Script, PrivateKey, PublicKey}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2PKH}
  alias BSV.Script.Address
  alias BSV.Tokens.Error
  alias BSV.Tokens.Script.StasBtgBuilder
  alias BSV.Tokens.Template.StasBtg, as: StasBtgTemplate
  alias BSV.Tokens.Template.StasBtgCheckpoint, as: CheckpointTemplate

  @type btg_payment :: %{
          txid: binary(),
          vout: non_neg_integer(),
          satoshis: non_neg_integer(),
          locking_script: Script.t(),
          private_key: PrivateKey.t(),
          prev_raw_tx: binary()
        }

  @type btg_transfer_config :: %{
          token_utxo: btg_payment(),
          destination: BSV.Tokens.Destination.t(),
          redemption_pkh: <<_::160>>,
          splittable: boolean(),
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  @type btg_split_config :: %{
          token_utxo: btg_payment(),
          destinations: [BSV.Tokens.Destination.t()],
          redemption_pkh: <<_::160>>,
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  @type btg_merge_config :: %{
          token_utxos: [btg_payment()],
          destination: BSV.Tokens.Destination.t(),
          redemption_pkh: <<_::160>>,
          splittable: boolean(),
          funding: BSV.Tokens.Payment.t(),
          fee_rate: non_neg_integer()
        }

  @type btg_checkpoint_config :: %{
          token_utxo: BSV.Tokens.Payment.t(),
          issuer_private_key: PrivateKey.t(),
          destination: BSV.Tokens.Destination.t(),
          redemption_pkh: <<_::160>>,
          splittable: boolean(),
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

  defp sign_btg_input(tx, index, private_key, prev_raw_tx, prev_vout) do
    template = StasBtgTemplate.unlock(private_key, prev_raw_tx, prev_vout)
    StasBtgTemplate.sign(template, tx, index)
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

  defp build_btg_outputs(destinations, redemption_pkh, splittable) do
    Enum.reduce_while(destinations, {:ok, []}, fn dest, {:ok, acc} ->
      with {:ok, owner_pkh} <- resolve_owner_pkh(dest.address),
           {:ok, script} <-
             StasBtgBuilder.build_stas_btg_locking_script(owner_pkh, redemption_pkh, splittable) do
        output = %Output{satoshis: dest.satoshis, locking_script: script}
        {:cont, {:ok, acc ++ [output]}}
      else
        error -> {:halt, error}
      end
    end)
  end

  # ---- Factory functions ----

  @doc "Build a BTG transfer transaction."
  @spec build_btg_transfer_tx(btg_transfer_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_btg_transfer_tx(config) do
    if config.destination.satoshis != config.token_utxo.satoshis do
      {:error, Error.amount_mismatch(config.token_utxo.satoshis, config.destination.satoshis)}
    else
      with {:ok, owner_pkh} <- resolve_owner_pkh(config.destination.address),
           {:ok, locking_script} <-
             StasBtgBuilder.build_stas_btg_locking_script(
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
             {:ok, sig0} <-
               sign_btg_input(
                 tx,
                 0,
                 config.token_utxo.private_key,
                 config.token_utxo.prev_raw_tx,
                 config.token_utxo.vout
               ),
             {:ok, sig1} <- sign_p2pkh_input(tx, 1, config.funding.private_key) do
          tx = tx |> set_unlocking_script(0, sig0) |> set_unlocking_script(1, sig1)
          {:ok, tx}
        end
      end
    end
  end

  @doc "Build a BTG split transaction."
  @spec build_btg_split_tx(btg_split_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_btg_split_tx(config) do
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
          with {:ok, token_outputs} <- build_btg_outputs(config.destinations, config.redemption_pkh, true) do
            tx = %Transaction{
              inputs: [make_input(config.token_utxo), make_input(config.funding)],
              outputs: token_outputs
            }

            with {:ok, tx} <- add_change_output(tx, config.funding, config.fee_rate),
                 {:ok, sig0} <-
                   sign_btg_input(
                     tx,
                     0,
                     config.token_utxo.private_key,
                     config.token_utxo.prev_raw_tx,
                     config.token_utxo.vout
                   ),
                 {:ok, sig1} <- sign_p2pkh_input(tx, 1, config.funding.private_key) do
              tx = tx |> set_unlocking_script(0, sig0) |> set_unlocking_script(1, sig1)
              {:ok, tx}
            end
          end
        end
    end
  end

  @doc "Build a BTG merge transaction."
  @spec build_btg_merge_tx(btg_merge_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_btg_merge_tx(config) do
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
                 StasBtgBuilder.build_stas_btg_locking_script(
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

              result =
                Enum.reduce_while(0..(length(config.token_utxos) - 1), {:ok, tx}, fn i, {:ok, tx} ->
                  utxo = Enum.at(config.token_utxos, i)

                  case sign_btg_input(tx, i, utxo.private_key, utxo.prev_raw_tx, utxo.vout) do
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

  @doc "Build a BTG checkpoint transaction."
  @spec build_btg_checkpoint_tx(btg_checkpoint_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_btg_checkpoint_tx(config) do
    if config.destination.satoshis != config.token_utxo.satoshis do
      {:error, Error.amount_mismatch(config.token_utxo.satoshis, config.destination.satoshis)}
    else
      with {:ok, owner_pkh} <- resolve_owner_pkh(config.destination.address),
           {:ok, locking_script} <-
             StasBtgBuilder.build_stas_btg_locking_script(
               owner_pkh,
               config.redemption_pkh,
               config.splittable
             ) do
        token_output = %Output{satoshis: config.destination.satoshis, locking_script: locking_script}

        tx = %Transaction{
          inputs: [make_input(config.token_utxo), make_input(config.funding)],
          outputs: [token_output]
        }

        with {:ok, tx} <- add_change_output(tx, config.funding, config.fee_rate) do
          checkpoint_template =
            CheckpointTemplate.unlock(config.token_utxo.private_key, config.issuer_private_key)

          with {:ok, sig0} <- CheckpointTemplate.sign(checkpoint_template, tx, 0),
               {:ok, sig1} <- sign_p2pkh_input(tx, 1, config.funding.private_key) do
            tx = tx |> set_unlocking_script(0, sig0) |> set_unlocking_script(1, sig1)
            {:ok, tx}
          end
        end
      end
    end
  end
end
