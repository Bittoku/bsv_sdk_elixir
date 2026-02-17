defmodule BSV.Tokens.Factory.Contract do
  @moduledoc """
  Contract transaction builder.

  Builds the initial contract transaction that establishes the token scheme
  on-chain.
  """

  alias BSV.{Crypto, Script, PrivateKey, PublicKey}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2PKH}
  alias BSV.Script.Address
  alias BSV.Tokens.{Error, Scheme}

  @type config :: %{
          scheme: Scheme.t(),
          funding_txid: binary(),
          funding_vout: non_neg_integer(),
          funding_satoshis: non_neg_integer(),
          funding_locking_script: Script.t(),
          funding_private_key: PrivateKey.t(),
          contract_satoshis: non_neg_integer(),
          fee_rate: non_neg_integer()
        }

  @doc "Build a contract transaction."
  @spec build_contract_tx(config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_contract_tx(config) do
    pubkey = PrivateKey.to_public_key(config.funding_private_key) |> PublicKey.compress()
    issuer_pkh = Crypto.hash160(pubkey.point)
    issuer_address = BSV.Base58.check_encode(issuer_pkh, 0x00)

    with {:ok, scheme_json} <- Scheme.to_json(config.scheme),
         {:ok, contract_script} <- Address.to_script(issuer_address) do
      # Build base transaction
      input = %Input{
        source_txid: config.funding_txid,
        source_tx_out_index: config.funding_vout,
        source_output: %Output{
          satoshis: config.funding_satoshis,
          locking_script: config.funding_locking_script
        }
      }

      contract_output = %Output{
        satoshis: config.contract_satoshis,
        locking_script: contract_script
      }

      op_return_output = %Output{
        satoshis: 0,
        locking_script: Script.op_return([scheme_json])
      }

      tx = %Transaction{
        inputs: [input],
        outputs: [contract_output, op_return_output]
      }

      # Estimate fee
      est_size = estimate_tx_size(tx, 1) + 34
      fee = div(est_size * config.fee_rate + 999, 1000)

      total_out = config.contract_satoshis + fee

      if config.funding_satoshis < total_out do
        {:error, Error.insufficient_funds(total_out, config.funding_satoshis)}
      else
        change = config.funding_satoshis - total_out

        tx =
          if change > 0 do
            {:ok, change_script} = Address.to_script(issuer_address)
            change_out = %Output{satoshis: change, locking_script: change_script, change: true}
            %{tx | outputs: tx.outputs ++ [change_out]}
          else
            tx
          end

        # Sign funding input
        unlocker = P2PKH.unlock(config.funding_private_key)

        case P2PKH.sign(unlocker, tx, 0) do
          {:ok, unlock_script} ->
            signed_input = %{Enum.at(tx.inputs, 0) | unlocking_script: unlock_script}
            {:ok, %{tx | inputs: [signed_input]}}

          error ->
            error
        end
      end
    end
  end

  defp estimate_tx_size(tx, num_p2pkh_inputs) do
    base = 4 + 1 + 1 + 4
    inputs_size = num_p2pkh_inputs * (32 + 4 + 1 + 106 + 4)

    outputs_size =
      Enum.reduce(tx.outputs, 0, fn out, acc ->
        acc + 8 + 1 + byte_size(Script.to_binary(out.locking_script))
      end)

    base + inputs_size + outputs_size
  end
end
