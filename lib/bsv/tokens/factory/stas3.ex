defmodule BSV.Tokens.Factory.Stas3 do
  @moduledoc """
  STAS3 transaction factories.

  Pure functions that build complete, signed transactions for STAS 3 token
  operations: two-tx issuance, base spend, freeze, unfreeze, and swap.
  """

  alias BSV.{Crypto, Script, PrivateKey, PublicKey}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2PKH, P2MPKH}
  alias BSV.Script.Address
  alias BSV.Tokens.Error
  alias BSV.Tokens.SigningKey
  alias BSV.Tokens.Script.{Stas3Builder, Templates}
  alias BSV.Tokens.Template.Stas3, as: Stas3Template

  # ---- Config types ----

  @type issue_config :: %{
          scheme: BSV.Tokens.Scheme.t(),
          funding_txid: binary(),
          funding_vout: non_neg_integer(),
          funding_satoshis: non_neg_integer(),
          funding_locking_script: Script.t(),
          funding_private_key: PrivateKey.t() | nil,
          funding_key: SigningKey.t() | nil,
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
          destinations: [BSV.Tokens.Stas3OutputParams.t()],
          spend_type: BSV.Tokens.Stas3SpendType.t(),
          fee_rate: non_neg_integer()
        }

  # ---- Helpers ----

  @doc false
  # Resolve the effective signing key from a config map.
  # Prefers `funding_key`, falls back to wrapping `funding_private_key` for backward compat.
  defp resolve_funding_key(config) do
    cond do
      Map.has_key?(config, :funding_key) and config.funding_key != nil ->
        config.funding_key

      Map.has_key?(config, :funding_private_key) and config.funding_private_key != nil ->
        SigningKey.single(config.funding_private_key)

      true ->
        raise "issue config has neither funding_key nor funding_private_key"
    end
  end

  # Build a locking script from a signing key (P2PKH address or bare P2MPKH).
  defp locking_script_from_signing_key({:single, key}) do
    address = change_address(key)
    Address.to_script(address)
  end

  # STAS 3.0 v0.1 §10.2: issuance/redemption boundary locking script for an
  # MPKH-owned UTXO is the fixed 70-byte body (NOT the bare-multisig redeem
  # buffer). The redeem buffer itself is only revealed at spend time on the
  # unlocking stack.
  defp locking_script_from_signing_key({:multi, _keys, multisig}) do
    mpkh = P2MPKH.mpkh(multisig)
    Script.from_binary(Templates.p2mpkh_locking_script(mpkh))
  end

  # Compute the 20-byte hash for a signing key (PKH or MPKH).
  defp hash160_from_signing_key(sk), do: SigningKey.hash160(sk)

  # Sign a transaction input using the appropriate template for a signing key.
  # For P2PKH, uses the standard P2PKH template.
  # For P2MPKH, uses the bare multisig P2MPKH template.
  defp sign_with_signing_key({:single, key}, tx, input_index) do
    unlocker = P2PKH.unlock(key)
    P2PKH.sign(unlocker, tx, input_index)
  end

  defp sign_with_signing_key({:multi, keys, multisig}, tx, input_index) do
    case P2MPKH.unlock(keys, multisig) do
      {:ok, unlocker} -> P2MPKH.sign(unlocker, tx, input_index)
      {:error, _} = err -> err
    end
  end

  # Derive an address string from a signing key (for change outputs).
  # P2PKH: Base58Check-encoded PKH.
  # P2MPKH: Not applicable for Base58 addresses — returns the PKH address of
  # the first key as a fallback for change. In practice, issuance change should
  # go back to the same locking script type, so we use locking_script_from_signing_key.
  defp change_address_from_signing_key({:single, key}), do: change_address(key)

  defp change_address_from_signing_key({:multi, _keys, _multisig} = _sk) do
    # P2MPKH change uses the same multisig locking script, not a Base58 address.
    # This function is only called for P2PKH; for P2MPKH, use locking_script_from_signing_key.
    raise "use locking_script_from_signing_key for P2MPKH change outputs"
  end

  # Add fee change output, dispatching on signing key type for the change script.
  defp add_fee_change_sk(tx, fee_satoshis, signing_key, fee_rate) do
    est_size = estimate_size(length(tx.inputs), tx.outputs) + 34
    fee = div(est_size * fee_rate + 999, 1000)

    if fee_satoshis < fee do
      {:error, Error.insufficient_funds(fee, fee_satoshis)}
    else
      change = fee_satoshis - fee

      tx =
        if change > 0 do
          {:ok, change_script} = locking_script_from_signing_key(signing_key)
          change_out = %Output{satoshis: change, locking_script: change_script, change: true}
          %{tx | outputs: tx.outputs ++ [change_out]}
        else
          tx
        end

      {:ok, tx}
    end
  end

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

  # STAS 3.0 v0.1 §9.5 / §10.3: select the unlocker variant for a token input.
  #
  # If the input's locking script is STAS 3.0 and its `owner` field equals
  # `EMPTY_HASH160` (the arbitrator-free / signature-suppression sentinel),
  # return a no-auth template that emits `OP_FALSE` instead of <sig> + pubkey.
  # Otherwise return the standard signing-key-driven template.
  @doc false
  def stas3_unlock_template_for(token_input, spend_type) do
    if BSV.Tokens.Script.Reader.arbitrator_free_owner?(token_input.locking_script) do
      Stas3Template.unlock_no_auth(spend_type)
    else
      sk = BSV.Tokens.TokenInput.resolve_signing_key(token_input)
      Stas3Template.unlock_from_signing_key(sk, spend_type)
    end
  end

  # ---- Factory functions ----

  @doc "Build the two-transaction STAS3 issuance flow."
  @spec build_stas3_issue_txs(issue_config()) ::
          {:ok, %{contract_tx: Transaction.t(), issue_tx: Transaction.t()}} | {:error, term()}
  def build_stas3_issue_txs(config) do
    if config.outputs == [] do
      {:error, Error.invalid_destination("at least one output required for STAS3 issuance")}
    else
      total_tokens = Enum.sum(Enum.map(config.outputs, & &1.satoshis))

      if total_tokens == 0 do
        {:error, Error.invalid_destination("total token satoshis must be > 0")}
      else
        # Resolve signing key: prefer funding_key, fall back to funding_private_key
        funding_sk = resolve_funding_key(config)
        issuer_pkh = hash160_from_signing_key(funding_sk)

        with {:ok, issuer_script} <- locking_script_from_signing_key(funding_sk),
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
                {:ok, change_script} = locking_script_from_signing_key(funding_sk)

                change_out = %Output{
                  satoshis: contract_change,
                  locking_script: change_script,
                  change: true
                }

                %{contract_tx | outputs: contract_tx.outputs ++ [change_out]}
              else
                contract_tx
              end

            # Sign contract TX (dispatches P2PKH or P2MPKH based on key type)
            with {:ok, sig} <- sign_with_signing_key(funding_sk, contract_tx, 0) do
              contract_tx = set_unlocking_script(contract_tx, 0, sig)
              contract_txid = Transaction.tx_id(contract_tx)

              # --- Issue TX ---
              {:ok, contract_out_script} = locking_script_from_signing_key(funding_sk)

              contract_input =
                make_input(contract_txid, 0, total_tokens, contract_out_script)

              issue_inputs =
                if contract_change > 0 do
                  {:ok, change_scr} = locking_script_from_signing_key(funding_sk)
                  change_input = make_input(contract_txid, 2, contract_change, change_scr)
                  [contract_input, change_input]
                else
                  [contract_input]
                end

              redemption_pkh = issuer_pkh

              # Build STAS3 token outputs
              with {:ok, token_outputs} <- build_stas3_outputs(config.outputs, redemption_pkh) do
                issue_tx = %Transaction{inputs: issue_inputs, outputs: token_outputs}

                # Fee change for issue TX
                fee_available = if contract_change > 0, do: contract_change, else: 0

                issue_tx =
                  if fee_available > 0 do
                    case add_fee_change_sk(
                           issue_tx,
                           fee_available,
                           funding_sk,
                           config.fee_rate
                         ) do
                      {:ok, tx} -> tx
                      _ -> issue_tx
                    end
                  else
                    issue_tx
                  end

                # Sign all issue TX inputs (dispatches P2PKH or P2MPKH)
                result =
                  Enum.reduce_while(0..(length(issue_tx.inputs) - 1), {:ok, issue_tx}, fn i,
                                                                                          {:ok,
                                                                                           tx} ->
                    case sign_with_signing_key(funding_sk, tx, i) do
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

  @doc "Build a generic STAS3 spend transaction."
  @spec build_stas3_base_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_base_tx(config) do
    cond do
      config.destinations == [] ->
        {:error, Error.invalid_destination("at least one destination required")}

      config.token_inputs == [] or length(config.token_inputs) > 2 ->
        {:error, Error.invalid_destination("STAS3 base tx requires 1 or 2 token inputs")}

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

          with {:ok, stas3_outputs} <- build_stas3_dest_outputs(config.destinations) do
            tx = %Transaction{
              inputs: token_inputs ++ [fee_input],
              outputs: stas3_outputs
            }

            with {:ok, tx} <-
                   add_fee_change(
                     tx,
                     config.fee_satoshis,
                     config.fee_private_key,
                     config.fee_rate
                   ) do
              # Sign token inputs with STAS3 template
              result =
                Enum.reduce_while(
                  0..(length(config.token_inputs) - 1),
                  {:ok, tx},
                  fn i, {:ok, tx} ->
                    ti = Enum.at(config.token_inputs, i)
                    template = stas3_unlock_template_for(ti, config.spend_type)

                    case Stas3Template.sign(template, tx, i) do
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

  @doc "Build a STAS3 freeze transaction."
  @spec build_stas3_freeze_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_freeze_tx(config) do
    frozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: true} end)

    build_stas3_base_tx(%{
      config
      | spend_type: :freeze_unfreeze,
        destinations: frozen_dests
    })
  end

  @doc "Build a STAS3 unfreeze transaction."
  @spec build_stas3_unfreeze_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_unfreeze_tx(config) do
    unfrozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: false} end)

    build_stas3_base_tx(%{
      config
      | spend_type: :freeze_unfreeze,
        destinations: unfrozen_dests
    })
  end

  @doc """
  Build a STAS3 split transaction.

  Splits a single STAS input into 1-4 STAS outputs. This is a semantic wrapper
  around `build_stas3_base_tx/1` that enforces split-specific constraints:
  exactly 1 STAS input and 1-4 destinations.

  ## Parameters
    * `config` - A `base_config()` map with:
      * `:token_inputs` - Exactly 1 token input
      * `:destinations` - 1-4 STAS3 output destinations
      * Other fields as per `base_config()`

  ## Returns
    * `{:ok, transaction}` on success
    * `{:error, reason}` on validation failure
  """
  @spec build_stas3_split_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_split_tx(config) do
    cond do
      length(config.token_inputs) != 1 ->
        {:error, Error.invalid_destination("split requires exactly 1 STAS input")}

      length(config.destinations) < 1 or length(config.destinations) > 4 ->
        {:error, Error.invalid_destination("split requires 1-4 destinations")}

      true ->
        build_stas3_base_tx(%{config | spend_type: :transfer})
    end
  end

  @doc """
  Build a STAS3 merge transaction.

  Merges exactly 2 STAS inputs into 1-2 STAS outputs. This is a semantic wrapper
  around `build_stas3_base_tx/1` that enforces merge-specific constraints.

  ## Parameters
    * `config` - A `base_config()` map with:
      * `:token_inputs` - Exactly 2 token inputs
      * `:destinations` - 1-2 STAS3 output destinations
      * Other fields as per `base_config()`

  ## Returns
    * `{:ok, transaction}` on success
    * `{:error, reason}` on validation failure
  """
  @spec build_stas3_merge_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_merge_tx(config) do
    cond do
      length(config.token_inputs) != 2 ->
        {:error, Error.invalid_destination("merge requires exactly 2 STAS inputs")}

      length(config.destinations) < 1 or length(config.destinations) > 2 ->
        {:error, Error.invalid_destination("merge requires 1-2 destinations")}

      true ->
        build_stas3_base_tx(%{config | spend_type: :transfer})
    end
  end

  @doc """
  Build a STAS3 confiscation transaction.

  Confiscates token UTXOs using spending type 3 (confiscation authority path).
  Frozen inputs CAN be confiscated. The scheme must have confiscation enabled
  and service fields must include the confiscation authority.

  ## Parameters
    * `config` - A `base_config()` map. The spend_type will be overridden
      to `:confiscation`.

  ## Returns
    * `{:ok, transaction}` on success
    * `{:error, reason}` on validation failure
  """
  @spec build_stas3_confiscate_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_confiscate_tx(config) do
    build_stas3_base_tx(%{config | spend_type: :confiscation})
  end

  @doc """
  Build a STAS3 redeem transaction.

  Redeems STAS tokens back to regular P2PKH satoshis. Only the issuer can redeem.
  This is NOT a wrapper around `build_stas3_base_tx/1` because the primary output
  is P2PKH rather than STAS3.

  ## Parameters
    * `config` - A map with:
      * `:token_input` - A single `TokenInput` (the STAS UTXO to redeem)
      * `:fee_txid`, `:fee_vout`, `:fee_satoshis`, `:fee_locking_script`,
        `:fee_private_key` - Funding input for fees
      * `:redeem_satoshis` - Amount to redeem as P2PKH output
      * `:redeem_pkh` - The 20-byte pubkey hash for the P2PKH redeem output
      * `:remaining_destinations` - Optional list of `Stas3OutputParams` for
        remaining STAS outputs (default `[]`)
      * `:fee_rate` - Fee rate in sat/KB

  ## Rules
    * Token input owner must be the issuer (owner_pkh == redemption_pkh from script)
    * Frozen inputs cannot be redeemed
    * Conservation: stas_in == redeem_satoshis + sum(remaining STAS outputs)
    * Uses spending type 1 (regular)

  ## Returns
    * `{:ok, transaction}` on success
    * `{:error, reason}` on validation failure
  """
  @spec build_stas3_redeem_tx(map()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_redeem_tx(config) do
    ti = config.token_input
    remaining = Map.get(config, :remaining_destinations, [])

    # Parse locking script to extract owner and redemption PKH
    parsed = BSV.Tokens.Script.Reader.read_locking_script(Script.to_binary(ti.locking_script))

    cond do
      parsed.script_type != :stas3 ->
        {:error, Error.invalid_script("token input is not a valid STAS3 script")}

      parsed.stas3.frozen ->
        {:error, Error.invalid_destination("frozen inputs cannot be redeemed")}

      parsed.stas3.owner != parsed.stas3.redemption ->
        {:error,
         Error.invalid_destination("only the issuer can redeem (owner must match redemption PKH)")}

      true ->
        total_remaining = Enum.sum(Enum.map(remaining, & &1.satoshis))
        expected = config.redeem_satoshis + total_remaining

        if ti.satoshis != expected do
          {:error, Error.amount_mismatch(ti.satoshis, expected)}
        else
          # Build redeem output — P2PKH or P2MPKH depending on config
          with {:ok, redeem_script} <- resolve_redeem_script(config) do
            redeem_output = %Output{
              satoshis: config.redeem_satoshis,
              locking_script: redeem_script
            }

            # Build optional remaining STAS3 outputs
            with {:ok, stas3_outputs} <- build_stas3_dest_outputs(remaining) do
              token_input =
                make_input(ti.txid, ti.vout, ti.satoshis, ti.locking_script)

              fee_input =
                make_input(
                  config.fee_txid,
                  config.fee_vout,
                  config.fee_satoshis,
                  config.fee_locking_script
                )

              tx = %Transaction{
                inputs: [token_input, fee_input],
                outputs: [redeem_output | stas3_outputs]
              }

              with {:ok, tx} <-
                     add_fee_change(
                       tx,
                       config.fee_satoshis,
                       config.fee_private_key,
                       config.fee_rate
                     ) do
                # Sign token input with STAS3 template (spending type 1 = regular).
                # Honour the §9.5 / §10.3 arbitrator-free no-auth path even on redeem,
                # so a redemption from an EMPTY_HASH160-owned UTXO can still be built.
                template = stas3_unlock_template_for(ti, :transfer)

                with {:ok, sig} <- Stas3Template.sign(template, tx, 0) do
                  tx = set_unlocking_script(tx, 0, sig)

                  # Sign fee input with P2PKH
                  unlocker = P2PKH.unlock(config.fee_private_key)

                  case P2PKH.sign(unlocker, tx, 1) do
                    {:ok, sig} -> {:ok, set_unlocking_script(tx, 1, sig)}
                    error -> error
                  end
                end
              end
            end
          end
        end
    end
  end

  @doc """
  Build a STAS3 transfer-swap transaction.

  One side transfers (spending type 1), the other side's swap request is consumed.
  Requires exactly 2 STAS inputs. Rejects frozen inputs.

  Outputs can be 2-4 STAS outputs:
  - Outputs 0-1: principal swap legs (neutral action data)
  - Output 2: optional remainder for leg 1
  - Output 3: optional remainder for leg 2

  ## Parameters
    * `config` - A `base_config()` map with exactly 2 token inputs and 2-4 destinations.

  ## Returns
    * `{:ok, transaction}` on success
    * `{:error, reason}` on validation failure (wrong input count, frozen inputs)
  """
  @spec build_stas3_transfer_swap_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_transfer_swap_tx(config) do
    with :ok <- validate_swap_inputs(config.token_inputs),
         :ok <- validate_swap_destinations(config.destinations) do
      dests = inherit_swap_remainders(config.token_inputs, config.destinations)
      build_stas3_base_tx(%{config | spend_type: :transfer, destinations: dests})
    end
  end

  @doc """
  Build a STAS3 swap-swap transaction.

  Both sides are swap requests (spending type 4). Requires exactly 2 STAS inputs,
  both carrying swap action data. Rejects frozen inputs.

  Outputs can be 2-4 STAS outputs:
  - Outputs 0-1: principal swap legs (neutral action data)
  - Output 2: optional remainder for leg 1
  - Output 3: optional remainder for leg 2

  ## Parameters
    * `config` - A `base_config()` map with exactly 2 token inputs and 2-4 destinations.

  ## Returns
    * `{:ok, transaction}` on success
    * `{:error, reason}` on validation failure (wrong input count, frozen inputs)
  """
  @spec build_stas3_swap_swap_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_swap_swap_tx(config) do
    with :ok <- validate_swap_inputs(config.token_inputs),
         :ok <- validate_swap_destinations(config.destinations) do
      dests = inherit_swap_remainders(config.token_inputs, config.destinations)
      build_stas3_base_tx(%{config | spend_type: :swap_cancellation, destinations: dests})
    end
  end

  @doc """
  Build a STAS3 swap flow transaction with auto-detected mode.

  Reads each input's locking script to detect swap action data:
  - Both inputs have swap action data → swap-swap (spending type 4)
  - Otherwise → transfer-swap (spending type 1)

  ## Parameters
    * `config` - A `base_config()` map with exactly 2 token inputs.

  ## Returns
    * `{:ok, transaction}` on success
    * `{:error, reason}` on validation failure
  """
  @spec build_stas3_swap_flow_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_swap_flow_tx(config) do
    if length(config.token_inputs) != 2 do
      {:error, Error.invalid_destination("swap flow requires exactly 2 token inputs")}
    else
      case resolve_stas3_swap_mode(config.token_inputs) do
        :swap_swap -> build_stas3_swap_swap_tx(config)
        :transfer_swap -> build_stas3_transfer_swap_tx(config)
      end
    end
  end

  @doc """
  Detect whether a swap is transfer-swap or swap-swap based on input locking scripts.

  Reads each input's locking script and checks for swap action data:
  - Both inputs have swap action data → `:swap_swap`
  - Otherwise → `:transfer_swap`

  ## Parameters
    * `token_inputs` - List of exactly 2 `TokenInput` structs

  ## Returns
    * `:swap_swap` or `:transfer_swap`
  """
  @spec resolve_stas3_swap_mode([BSV.Tokens.TokenInput.t()]) :: :swap_swap | :transfer_swap
  def resolve_stas3_swap_mode(token_inputs) when length(token_inputs) == 2 do
    swap_count =
      Enum.count(token_inputs, fn ti ->
        parsed =
          BSV.Tokens.Script.Reader.read_locking_script(Script.to_binary(ti.locking_script))

        parsed.script_type == :stas3 and
          parsed.stas3 != nil and
          match?({:swap, %{}}, parsed.stas3.action_data_parsed)
      end)

    if swap_count == 2, do: :swap_swap, else: :transfer_swap
  end

  # ---- Private helpers ----

  # Resolve the redeem output locking script from config.
  # Supports three modes:
  #   1. `redeem_key` (SigningKey) — dispatches P2PKH or P2MPKH locking script
  #   2. `redeem_multisig` (multisig_script) — bare P2MPKH locking script
  #   3. `redeem_pkh` (20-byte hash, default) — P2PKH locking script
  defp resolve_redeem_script(config) do
    cond do
      Map.has_key?(config, :redeem_key) and config.redeem_key != nil ->
        locking_script_from_signing_key(config.redeem_key)

      Map.has_key?(config, :redeem_multisig) and config.redeem_multisig != nil ->
        # Spec v0.1 §10.2: redemption boundary uses the fixed 70-byte
        # P2MPKH locking script (HASH160 of the redeem buffer, never the
        # bare buffer itself).
        mpkh = P2MPKH.mpkh(config.redeem_multisig)
        Script.from_binary(Templates.p2mpkh_locking_script(mpkh))

      true ->
        redeem_address = BSV.Base58.check_encode(config.redeem_pkh, 0x00)
        Address.to_script(redeem_address)
    end
  end

  defp build_stas3_outputs(outputs, redemption_pkh) do
    Enum.reduce_while(outputs, {:ok, []}, fn out, {:ok, acc} ->
      case Stas3Builder.build_stas3_locking_script(
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

  defp build_stas3_dest_outputs(destinations) do
    Enum.reduce_while(destinations, {:ok, []}, fn dest, {:ok, acc} ->
      case Stas3Builder.build_stas3_locking_script(
             dest.owner_pkh,
             dest.redemption_pkh,
             dest.action_data,
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

  # Validate swap inputs: exactly 2, none frozen
  defp validate_swap_inputs(token_inputs) do
    cond do
      length(token_inputs) != 2 ->
        {:error, Error.invalid_destination("swap requires exactly 2 token inputs")}

      true ->
        frozen =
          Enum.any?(token_inputs, fn ti ->
            parsed =
              BSV.Tokens.Script.Reader.read_locking_script(Script.to_binary(ti.locking_script))

            parsed.script_type == :stas3 and parsed.stas3 != nil and parsed.stas3.frozen
          end)

        if frozen do
          {:error, Error.invalid_destination("frozen inputs cannot be swapped")}
        else
          :ok
        end
    end
  end

  # STAS 3.0 v0.1 §9.5: "Remainder / split outputs inherit the source UTXO's
  # both owner and var2 fields." For a swap with N STAS outputs:
  #   * outputs 0..1   = principal legs (caller-controlled)
  #   * output 2 (if present) = remainder for leg 1 → inherits from input 0
  #   * output 3 (if present) = remainder for leg 2 → inherits from input 1
  #
  # We rewrite remainder destinations in-place so the resulting locking script
  # has both `owner_pkh` and `action_data` (var2) byte-identical to the source
  # input — preserving the swap descriptor for any unmatched balance.
  @doc false
  def inherit_swap_remainders(token_inputs, destinations) do
    destinations
    |> Enum.with_index()
    |> Enum.map(fn
      {dest, 2} ->
        inherit_from_source(dest, Enum.at(token_inputs, 0))

      {dest, 3} ->
        inherit_from_source(dest, Enum.at(token_inputs, 1))

      {dest, _} ->
        dest
    end)
  end

  defp inherit_from_source(dest, nil), do: dest

  defp inherit_from_source(dest, ti) do
    parsed = BSV.Tokens.Script.Reader.read_locking_script(Script.to_binary(ti.locking_script))

    case parsed do
      %{script_type: :stas3, stas3: %{owner: owner} = f} when not is_nil(owner) ->
        action_data = source_action_data(f)
        %{dest | owner_pkh: owner, action_data: action_data}

      _ ->
        dest
    end
  end

  # Recover the original action_data tuple from a parsed STAS 3.0 frame.
  defp source_action_data(%{action_data_parsed: nil, action_data_raw: <<>>}), do: nil
  defp source_action_data(%{action_data_parsed: nil, action_data_raw: nil}), do: nil
  defp source_action_data(%{action_data_parsed: nil, action_data_raw: <<0x52>>}), do: nil

  defp source_action_data(%{action_data_parsed: parsed}) when not is_nil(parsed),
    do: parsed

  defp source_action_data(%{action_data_raw: raw}) when is_binary(raw) and byte_size(raw) > 0,
    do: {:custom, raw}

  defp source_action_data(_), do: nil

  # Validate swap destinations: 2-4 outputs
  defp validate_swap_destinations(destinations) do
    count = length(destinations)

    if count < 2 or count > 4 do
      {:error, Error.invalid_destination("swap requires 2-4 destinations")}
    else
      :ok
    end
  end
end
