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
  alias BSV.Tokens.Script.{Stas3Builder, Stas3Pieces, Templates, Reader}
  alias BSV.Tokens.ScriptFlags
  alias BSV.Tokens.Stas3.Validate, as: Stas3Validate
  alias BSV.Tokens.Template.Stas3, as: Stas3Template
  alias BSV.Tokens.Factory.Stas3.WitnessBuilder

  # ---- Config types ----

  @type issue_config :: %{
          scheme: BSV.Tokens.Scheme.t(),
          funding_txid: binary(),
          funding_vout: non_neg_integer(),
          funding_satoshis: non_neg_integer(),
          funding_locking_script: Script.t(),
          funding_private_key: PrivateKey.t() | nil,
          funding_key: SigningKey.t() | nil,
          outputs: [
            %{
              required(:satoshis) => non_neg_integer(),
              required(:owner_pkh) => <<_::160>>,
              optional(:freezable) => boolean(),
              optional(:confiscatable) => boolean(),
              optional(:nft) => boolean(),
              optional(:augmentable) => boolean(),
              optional(:action_data) => BSV.Tokens.ActionData.t() | nil
            }
          ],
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
  #
  # When a `witness` (BSV.Tokens.Stas3UnlockWitness.t()) is supplied, attach
  # it to the template via `with_witness/2` so the produced unlock script is
  # `witness ‖ authz` per spec §7. Witness defaults to `nil` for callers
  # that want only the legacy authz block (back-compat).
  @doc false
  def stas3_unlock_template_for(token_input, spend_type, witness \\ nil) do
    template =
      if BSV.Tokens.Script.Reader.arbitrator_free_owner?(token_input.locking_script) do
        Stas3Template.unlock_no_auth(spend_type)
      else
        sk = BSV.Tokens.TokenInput.resolve_signing_key(token_input)
        Stas3Template.unlock_from_signing_key(sk, spend_type)
      end

    case witness do
      nil -> template
      %BSV.Tokens.Stas3UnlockWitness{} = w -> Stas3Template.with_witness(template, w)
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

      # Spec §15.1: a plain-transfer spend consuming an NFT must consume exactly
      # one STAS input (non-mergeable) and produce exactly one output
      # (non-splittable). Only the transfer funnel is gated; swap (via its own
      # validator) and confiscation carry their own output semantics and reject
      # NFT inputs upstream.
      Map.get(config, :spend_type) == :transfer and
        Enum.any?(config.token_inputs, &Stas3Validate.nft?/1) and
          length(config.token_inputs) != 1 ->
        {:error, :nft_not_mergeable}

      Map.get(config, :spend_type) == :transfer and
        Enum.any?(config.token_inputs, &Stas3Validate.nft?/1) and
          length(config.destinations) != 1 ->
        {:error, :nft_output_count}

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

          # Spec §5.2.2 / §15: STAS 3.0 capability flags are immutable across a
          # spend, so force every destination to carry the consumed inputs'
          # capability flags before building outputs (see
          # `enforce_input_capability_flags/2`).
          enforced_destinations =
            enforce_input_capability_flags(config.token_inputs, config.destinations)

          with {:ok, stas3_outputs} <- build_stas3_dest_outputs(enforced_destinations) do
            # Spec §6.4 / §15.2: if a consumed NFT+AUGMENTABLE input carries an
            # augmentation directive, append its data to the sole token output
            # (the NFT invariant guarantees exactly one) before signing so the
            # input signatures commit to the appended tail.
            stas3_outputs = apply_augment_directive(stas3_outputs, config)

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
              # Sign token inputs with STAS3 template, attaching the
              # auto-derived spec §7 witness for each.
              fee_idx = length(config.token_inputs)
              tx_type = Map.get(config, :tx_type, :regular)
              sighash_flag = Map.get(config, :sighash_flag, 0x41)

              result =
                Enum.reduce_while(
                  0..(length(config.token_inputs) - 1),
                  {:ok, tx},
                  fn i, {:ok, tx} ->
                    ti = Enum.at(config.token_inputs, i)

                    with {:ok, witness} <-
                           WitnessBuilder.derive_witness_for_input(
                             tx,
                             i,
                             fee_idx,
                             config.spend_type,
                             tx_type,
                             sighash_flag
                           ),
                         template = stas3_unlock_template_for(ti, config.spend_type, witness),
                         {:ok, sig} <- Stas3Template.sign(template, tx, i) do
                      {:cont, {:ok, set_unlocking_script(tx, i, sig)}}
                    else
                      error -> {:halt, error}
                    end
                  end
                )

              with {:ok, tx} <- result do
                # Sign fee input with P2PKH
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

  @doc """
  Build a STAS3 freeze transaction.

  Per spec §9.2 (enforced before signing via `BSV.Tokens.Stas3.Validate.freeze/2`):

    * exactly one destination (a single STAS output),
    * `owner_pkh` and `redemption_pkh` byte-identical to the input,
    * the input's `flags` field has the FREEZABLE bit set.

  Returns `{:error, :freeze_output_count}`, `{:error, :freeze_field_drift}`,
  or `{:error, :freeze_flag_not_set}` on validation failure.
  """
  @spec build_stas3_freeze_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_freeze_tx(config) do
    frozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: true} end)

    with :ok <- Stas3Validate.freeze(hd(config.token_inputs), frozen_dests) do
      build_stas3_base_tx(
        config
        |> Map.put(:spend_type, :freeze_unfreeze)
        |> Map.put(:destinations, frozen_dests)
        |> Map.put_new(:tx_type, :regular)
      )
    end
  end

  @doc """
  Build a STAS3 unfreeze transaction.

  Same §9.2 constraints as `build_stas3_freeze_tx/1`.
  """
  @spec build_stas3_unfreeze_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_unfreeze_tx(config) do
    unfrozen_dests = Enum.map(config.destinations, fn d -> %{d | frozen: false} end)

    with :ok <- Stas3Validate.freeze(hd(config.token_inputs), unfrozen_dests) do
      build_stas3_base_tx(
        config
        |> Map.put(:spend_type, :freeze_unfreeze)
        |> Map.put(:destinations, unfrozen_dests)
        |> Map.put_new(:tx_type, :regular)
      )
    end
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

      # Spec §15.1: an NFT is indivisible — splitting it is forbidden outright.
      Enum.any?(config.token_inputs, &Stas3Validate.nft?/1) ->
        {:error, :nft_not_splittable}

      true ->
        build_stas3_base_tx(
          config
          |> Map.put(:spend_type, :transfer)
          |> Map.put_new(:tx_type, :regular)
        )
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

      # Spec §15.1: an NFT is non-mergeable — reject if either input is an NFT.
      Enum.any?(config.token_inputs, &Stas3Validate.nft?/1) ->
        {:error, :nft_not_mergeable}

      true ->
        # Two-input merge → §8.1 txType = :merge_2.
        build_stas3_base_tx(
          config
          |> Map.put(:spend_type, :transfer)
          |> Map.put_new(:tx_type, :merge_2)
        )
    end
  end

  @doc """
  Build a STAS3 confiscation transaction.

  Per spec §9.3 (enforced before signing via
  `BSV.Tokens.Stas3.Validate.confiscation/1`):

    * the input's `flags` field has the CONFISCATABLE bit set,
    * frozen inputs CAN be confiscated (spec §9.6: confiscation has the
      highest precedence and is permitted to override freeze).

  Returns `{:error, :confiscate_flag_not_set}` if the flag is missing.

  Spec §9.6 precedence (informative — independent factories choose intent):
  Confiscation > Freeze > Swap > Regular spend.
  """
  @spec build_stas3_confiscate_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_confiscate_tx(config) do
    with :ok <- validate_all(config.token_inputs, &Stas3Validate.confiscation/1),
         :ok <- reject_nft_spend_path(config.token_inputs) do
      # Confiscation respects the caller's `:tx_type` if provided; defaults
      # to `:regular` (txType byte 0) per §4 / §9.3 (no encoded restriction).
      build_stas3_base_tx(
        config
        |> Map.put(:spend_type, :confiscation)
        |> Map.put_new(:tx_type, :regular)
      )
    end
  end

  @doc """
  Build a STAS3 swap-cancellation transaction (spec §9.4).

  Cancels a standing swap offer by spending the maker's swap-descriptor
  UTXO back to its `var2.receiveAddr` owner. Constraints (enforced via
  `BSV.Tokens.Stas3.Validate.swap_cancel/2`):

    * exactly 1 token input whose `var2` is a swap descriptor (action 0x01),
    * exactly 1 destination,
    * destination's `owner_pkh` equals the input's `var2.receiveAddr`.

  The unlocking script uses spendType = 4. Authorisation against
  `receiveAddr` is enforced by the engine at spend time.

  Returns `{:error, :swap_cancel_missing_descriptor}`,
  `{:error, :swap_cancel_output_count}`, or
  `{:error, :swap_cancel_owner_mismatch}` on validation failure.
  """
  @spec build_stas3_swap_cancel_tx(base_config()) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_swap_cancel_tx(config) do
    cond do
      length(config.token_inputs) != 1 ->
        {:error, Error.invalid_destination("swap cancellation requires exactly 1 token input")}

      true ->
        with :ok <- reject_nft_spend_path(config.token_inputs),
             :ok <- Stas3Validate.swap_cancel(hd(config.token_inputs), config.destinations) do
          build_stas3_base_tx(
            config
            |> Map.put(:spend_type, :swap_cancellation)
            |> Map.put_new(:tx_type, :regular)
          )
        end
    end
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
                tx_type = Map.get(config, :tx_type, :regular)
                sighash_flag = Map.get(config, :sighash_flag, 0x41)

                with {:ok, witness} <-
                       WitnessBuilder.derive_witness_for_input(
                         tx,
                         0,
                         1,
                         :transfer,
                         tx_type,
                         sighash_flag
                       ),
                     template = stas3_unlock_template_for(ti, :transfer, witness),
                     {:ok, sig} <- Stas3Template.sign(template, tx, 0) do
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

      build_stas3_base_tx(
        config
        |> Map.put(:spend_type, :transfer)
        |> Map.put(:destinations, dests)
        |> Map.put_new(:tx_type, :atomic_swap)
      )
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

      # Spec §9.5: atomic swap uses spendType = 1 (Transfer) on BOTH STAS
      # inputs. SwapCancellation (4) is reserved for §9.4 swap-cancel; using
      # it here would be a spec violation (this matched the prior bug fixed
      # in the Rust SDK). The atomic-swap "shape" is signalled by tx_type
      # AtomicSwap (1) plus the trailing piece-array params, not by spend_type.
      build_stas3_base_tx(
        config
        |> Map.put(:spend_type, :transfer)
        |> Map.put(:destinations, dests)
        |> Map.put_new(:tx_type, :atomic_swap)
      )
    end
  end

  @doc """
  Build a STAS3 swap-swap transaction with the spec §9.5 trailing
  `<counterparty_script> <piece_count> <piece_array>` block auto-wired
  into BOTH inputs' unlocking scripts.

  Use this entry point when the resulting tx must satisfy engine-level
  verification — i.e. an actual on-chain spend rather than a witness
  shape test. For each input `i`, the appended trailing block contains:

    * `counterparty_script` — the OTHER input's locking script (raw bytes).
    * `piece_count` — derived from `pieces[i]` (number of pieces produced
      from `preceding_tx` after excising the asset script at
      `asset_output_index`).
    * `piece_array` — reverse-ordered, length-prefixed (1-byte length, then
      body) — matching the engine ASM's `OP_1 OP_SPLIT OP_IFDUP OP_IF
      OP_SWAP OP_SPLIT OP_ENDIF` consumption pattern.

  `pieces` MUST be a list of EXACTLY 2 maps, each with `:preceding_tx`
  (binary) and `:asset_output_index` (non-negative integer) keys.

  Mirrors `bsv-sdk-rust::build_stas3_swap_swap_tx_with_pieces/2`.

  Returns `{:error, reason}` for the same input-shape failures as
  `build_stas3_swap_swap_tx/1` (frozen inputs, wrong count) plus piece
  encoding errors propagated from `Stas3Pieces`.
  """
  @spec build_stas3_swap_swap_tx_with_pieces(
          base_config(),
          [
            %{
              required(:preceding_tx) => binary(),
              required(:asset_output_index) => non_neg_integer()
            }
          ]
        ) :: {:ok, Transaction.t()} | {:error, term()}
  def build_stas3_swap_swap_tx_with_pieces(config, pieces)
      when is_list(pieces) and length(pieces) == 2 do
    with {:ok, tx} <- build_stas3_swap_swap_tx(config) do
      append_swap_trailing_pieces(tx, config.token_inputs, pieces)
    end
  end

  def build_stas3_swap_swap_tx_with_pieces(_config, _pieces),
    do:
      {:error, Error.invalid_destination("swap-swap with pieces requires exactly 2 piece params")}

  # Splice the spec §9.5 DXS-aligned trailing block IN PLACE OF the bare
  # txType byte at slot 18 for BOTH STAS inputs' unlocking scripts.
  # Mirrors `bsv-sdk-rust`'s `build_stas3_swap_swap_tx_with_pieces`.
  #
  # Layout (push order):
  #   push(counterparty_vout)         numeric
  #   push(pieces[0]) … push(pieces[N-1])  raw pushdata each
  #   push(piece_count)               numeric
  #   push(counterparty_asset_tail)   raw pushdata
  #   push(1)                         numeric — "swap marker"
  #
  # Pieces come from the COUNTERPARTY's preceding_tx (not own); the
  # engine uses them to cross-verify the other leg's back-to-genesis
  # ancestor. `counterparty_asset_tail` is the bytes after owner_push +
  # var2_push in the counterparty's locking script.
  defp append_swap_trailing_pieces(tx, token_inputs, pieces) do
    Enum.reduce_while(0..1, {:ok, tx}, fn i, {:ok, acc_tx} ->
      counterparty_idx = 1 - i

      counterparty_locking_bin =
        token_inputs
        |> Enum.at(counterparty_idx)
        |> Map.fetch!(:locking_script)
        |> Script.to_binary()

      case extract_stas3_asset_tail(counterparty_locking_bin) do
        nil ->
          {:halt, {:error, :counterparty_not_stas3_shaped}}

        counterparty_tail ->
          counterparty_vout =
            tx.inputs
            |> Enum.at(counterparty_idx)
            |> Map.fetch!(:source_tx_out_index)

          counterparty_piece_params = Enum.at(pieces, counterparty_idx)
          counterparty_preceding_tx = Map.fetch!(counterparty_piece_params, :preceding_tx)
          counterparty_asset_index = Map.fetch!(counterparty_piece_params, :asset_output_index)

          # Spec §9.5 back-to-genesis: the asset script must be excised from
          # the SPECIFIC output the counterparty input spends
          # (`asset_output_index`), not from every output whose tail happens
          # to match. Deriving pieces from the wrong output would produce an
          # invalid reconstruction for preceding txs with multiple STAS-like
          # outputs (note 2231 §5).
          case split_preceding_tx_at_output(
                 counterparty_preceding_tx,
                 counterparty_tail,
                 counterparty_asset_index
               ) do
            {:ok, counterparty_pieces} ->
              trailing_bytes =
                minimal_numeric_push(counterparty_vout) <>
                  Enum.reduce(counterparty_pieces, <<>>, fn p, acc -> acc <> pushdata(p) end) <>
                  minimal_numeric_push(length(counterparty_pieces)) <>
                  pushdata(counterparty_tail) <>
                  minimal_numeric_push(1)

              case splice_swap_trailing_in_place_of_tx_type(acc_tx, i, trailing_bytes) do
                {:ok, updated_tx} -> {:cont, {:ok, updated_tx}}
                {:error, _} = err -> {:halt, err}
              end

            {:error, _} = err ->
              {:halt, err}
          end
      end
    end)
  end

  # Extract the asset-script tail from a STAS 3.0 locking script:
  # everything after `[OP_DATA_20 + 20B owner_pkh][var2 push]`. Returns
  # nil if the script isn't STAS-shaped.
  defp extract_stas3_asset_tail(<<0x14, _owner::binary-size(20), rest::binary>>) do
    case skip_one_push(rest) do
      nil -> nil
      remaining -> remaining
    end
  end

  defp extract_stas3_asset_tail(_), do: nil

  # Skip a single Bitcoin push opcode and return the remaining bytes.
  defp skip_one_push(<<0x00, rest::binary>>), do: rest
  defp skip_one_push(<<0x4F, rest::binary>>), do: rest

  defp skip_one_push(<<op, rest::binary>>) when op >= 0x51 and op <= 0x60, do: rest

  defp skip_one_push(<<len, _body::binary-size(len), rest::binary>>)
       when len >= 0x01 and len <= 0x4B,
       do: rest

  defp skip_one_push(<<0x4C, len, _body::binary-size(len), rest::binary>>), do: rest

  defp skip_one_push(<<0x4D, len::little-16, _body::binary-size(len), rest::binary>>), do: rest

  defp skip_one_push(<<0x4E, len::little-32, _body::binary-size(len), rest::binary>>), do: rest

  defp skip_one_push(_), do: nil

  # Split `preceding_tx` around the `asset_tail` occurrence that belongs to the
  # output at `asset_output_index`, returning the two gap pieces
  # `[after, before]` in reverse-of-tx-order (later gap first) — the order the
  # canonical engine expects. Mirrors DXS
  # `splitDstasPreviousTransactionByCounterpartyScript` + `.reverse()`, but
  # excises ONLY the named asset output's script rather than every tail match,
  # so a preceding tx with multiple STAS-like outputs reconstructs correctly
  # (note 2231 §5).
  @spec split_preceding_tx_at_output(binary(), binary(), non_neg_integer()) ::
          {:ok, [binary()]} | {:error, term()}
  defp split_preceding_tx_at_output(preceding_tx, asset_tail, asset_output_index)
       when byte_size(asset_tail) > 0 do
    with {:ok, {script_start, script_len}} <-
           Stas3Pieces.locate_output_script(preceding_tx, asset_output_index) do
      script_bytes = binary_part(preceding_tx, script_start, script_len)

      case :binary.match(script_bytes, asset_tail) do
        :nomatch ->
          {:error, {:asset_tail_not_in_output, asset_output_index}}

        {rel_pos, len} ->
          abs_pos = script_start + rel_pos
          before = binary_part(preceding_tx, 0, abs_pos)

          after_tail =
            binary_part(preceding_tx, abs_pos + len, byte_size(preceding_tx) - abs_pos - len)

          {:ok, [after_tail, before]}
      end
    end
  end

  # Minimal Bitcoin numeric push.
  defp minimal_numeric_push(0), do: <<0x00>>
  defp minimal_numeric_push(n) when n in 1..16, do: <<0x50 + n>>

  defp minimal_numeric_push(n) when n >= 17 and n <= 127, do: <<0x01, n>>

  defp minimal_numeric_push(n) when n >= 128 and n <= 0xFF, do: <<0x02, n, 0x00>>

  # Encode `n` (must be > 0xFF) as a sign-bit-safe minimal little-endian
  # script-num push.
  defp minimal_numeric_push(n) when is_integer(n) and n > 0xFF do
    bytes = encode_le_minimal(n)
    <<byte_size(bytes), bytes::binary>>
  end

  defp encode_le_minimal(0), do: <<>>

  defp encode_le_minimal(n) when n > 0 do
    bytes = do_le_bytes(n, <<>>)
    <<last>> = binary_part(bytes, byte_size(bytes) - 1, 1)

    if Bitwise.band(last, 0x80) != 0 do
      bytes <> <<0x00>>
    else
      bytes
    end
  end

  defp do_le_bytes(0, acc), do: acc

  defp do_le_bytes(n, acc) do
    do_le_bytes(Bitwise.bsr(n, 8), acc <> <<Bitwise.band(n, 0xFF)>>)
  end

  # Standard Bitcoin pushdata framing.
  defp pushdata(<<>>), do: <<0x00>>

  defp pushdata(data) when byte_size(data) <= 75,
    do: <<byte_size(data)::8, data::binary>>

  defp pushdata(data) when byte_size(data) <= 255,
    do: <<0x4C, byte_size(data)::8, data::binary>>

  defp pushdata(data) when byte_size(data) <= 0xFFFF,
    do: <<0x4D, byte_size(data)::little-16, data::binary>>

  defp pushdata(data),
    do: <<0x4E, byte_size(data)::little-32, data::binary>>

  # Splice `trailing_bytes` into the unlocking script of `tx.inputs[idx]`
  # in place of the bare txType chunk (the 5th-from-end push). The tail
  # of the unlocking script is expected to be:
  #
  #   `[…§7 slots…][txType 1B][preimage][spendType 1B][signature][pubkey]`
  defp splice_swap_trailing_in_place_of_tx_type(tx, input_index, trailing_bytes) do
    input = Enum.at(tx.inputs, input_index)

    case input.unlocking_script do
      %Script{} = existing ->
        existing_bin = Script.to_binary(existing)

        with {:ok, before_bytes, _tx_type_bytes, after_bytes} <-
               split_at_tx_type_chunk(existing_bin) do
          combined_bin = before_bytes <> trailing_bytes <> after_bytes

          case Script.from_binary(combined_bin) do
            {:ok, %Script{} = combined} ->
              {:ok, set_unlocking_script(tx, input_index, combined)}

            {:error, _} = err ->
              err
          end
        end

      _ ->
        {:error, :missing_unlocking_script}
    end
  end

  # Walk the unlocking script and return (before_bytes, tx_type_chunk_bytes,
  # after_bytes) where tx_type_chunk_bytes is the 5th-from-end chunk's
  # serialised bytes. Assumes the last 5 chunks are
  # [txType, preimage, spendType, sig, pubkey].
  defp split_at_tx_type_chunk(bin) do
    case parse_all_chunks(bin) do
      {:ok, chunks} when length(chunks) >= 5 ->
        tx_type_idx = length(chunks) - 5
        before_chunks = Enum.take(chunks, tx_type_idx)
        tx_type_chunk = Enum.at(chunks, tx_type_idx)
        # IMPORTANT: `Enum.drop(chunks, tx_type_idx + 1)` returns the
        # chunks AFTER txType (preimage, spendType, sig, pubkey). Using
        # `List.pop_at` here would return the whole list minus the
        # popped item — i.e. would duplicate the §7 slots BEFORE the
        # splice point.
        after_chunks = Enum.drop(chunks, tx_type_idx + 1)

        before_bytes =
          Enum.reduce(before_chunks, <<>>, fn {_, bytes}, acc -> acc <> bytes end)

        {_, tx_type_bytes} = tx_type_chunk

        after_bytes =
          Enum.reduce(after_chunks, <<>>, fn {_, bytes}, acc -> acc <> bytes end)

        {:ok, before_bytes, tx_type_bytes, after_bytes}

      {:ok, chunks} ->
        {:error, {:too_few_chunks, length(chunks)}}

      {:error, _} = err ->
        err
    end
  end

  # Walk Bitcoin script bytes returning a list of {opcode, full_chunk_bytes}.
  defp parse_all_chunks(bin), do: parse_chunks_loop(bin, [])

  defp parse_chunks_loop(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp parse_chunks_loop(<<0x00, rest::binary>>, acc),
    do: parse_chunks_loop(rest, [{0x00, <<0x00>>} | acc])

  defp parse_chunks_loop(<<op, rest::binary>>, acc)
       when op >= 0x4F and op <= 0x60 and op != 0x50,
       do: parse_chunks_loop(rest, [{op, <<op>>} | acc])

  defp parse_chunks_loop(<<len, body::binary-size(len), rest::binary>>, acc)
       when len >= 0x01 and len <= 0x4B do
    chunk = <<len, body::binary>>
    parse_chunks_loop(rest, [{len, chunk} | acc])
  end

  defp parse_chunks_loop(<<0x4C, len, body::binary-size(len), rest::binary>>, acc) do
    chunk = <<0x4C, len, body::binary>>
    parse_chunks_loop(rest, [{0x4C, chunk} | acc])
  end

  defp parse_chunks_loop(<<0x4D, len::little-16, body::binary-size(len), rest::binary>>, acc) do
    chunk = <<0x4D, len::little-16, body::binary>>
    parse_chunks_loop(rest, [{0x4D, chunk} | acc])
  end

  defp parse_chunks_loop(<<0x4E, len::little-32, body::binary-size(len), rest::binary>>, acc) do
    chunk = <<0x4E, len::little-32, body::binary>>
    parse_chunks_loop(rest, [{0x4E, chunk} | acc])
  end

  defp parse_chunks_loop(<<op, rest::binary>>, acc),
    do: parse_chunks_loop(rest, [{op, <<op>>} | acc])

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
      flags = %ScriptFlags{
        freezable: Map.get(out, :freezable, true),
        confiscatable: Map.get(out, :confiscatable, false),
        nft: Map.get(out, :nft, false),
        augmentable: Map.get(out, :augmentable, false)
      }

      # Reject a standalone AUGMENTABLE bit at mint time (§15.2); encode the full
      # flags byte and select the engine (0.0.11 for NFT/AUGMENTABLE). An
      # optional `action_data` mints the token with a var2 directive (§6.4).
      with :ok <- ScriptFlags.validate(flags),
           {:ok, script} <-
             Stas3Builder.build_stas3_locking_script_with_engine(
               out.owner_pkh,
               redemption_pkh,
               Map.get(out, :action_data, nil),
               false,
               flags,
               ScriptFlags.engine(flags),
               [],
               []
             ) do
        output = %Output{satoshis: out.satoshis, locking_script: script}
        {:cont, {:ok, acc ++ [output]}}
      else
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp build_stas3_dest_outputs(destinations) do
    Enum.reduce_while(destinations, {:ok, []}, fn dest, {:ok, acc} ->
      flags = dest_flags(dest)

      case Stas3Builder.build_stas3_locking_script_with_engine(
             dest.owner_pkh,
             dest.redemption_pkh,
             dest.action_data,
             dest.frozen,
             flags,
             ScriptFlags.engine(flags),
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

  # Spec §5.2.2 / §15: the four STAS 3.0 capability flags (freezable,
  # confiscatable, nft, augmentable) are fixed at issuance and immutable across
  # every spend. When all consumed token inputs carry an identical capability
  # set — the same-token case (transfer / split / merge / freeze / confiscation)
  # — force every produced token output to that canonical set so a destination
  # can neither silently strip nor add a capability bit, and so engine selection
  # follows `ScriptFlags.engine/1` (0.0.11 whenever NFT/AUGMENTABLE is preserved).
  # A heterogeneous input set (a two-token atomic swap) is left untouched; those
  # paths carry their own semantics and reject NFT inputs upstream.
  defp enforce_input_capability_flags(token_inputs, destinations) do
    case canonical_input_flags(token_inputs) do
      {:ok, %ScriptFlags{} = flags} ->
        Enum.map(destinations, &put_capability_flags(&1, flags))

      :mixed ->
        destinations
    end
  end

  # `{:ok, flags}` when every token input decodes as a STAS 3.0 frame carrying an
  # identical capability-flag set, else `:mixed` (skip enforcement).
  defp canonical_input_flags(token_inputs) do
    case Enum.map(token_inputs, &input_capability_flags/1) do
      [%ScriptFlags{} = first | rest] ->
        if Enum.all?(rest, &(&1 == first)), do: {:ok, first}, else: :mixed

      _ ->
        :mixed
    end
  end

  # Decoded capability flags of a token input, or nil if it does not parse as a
  # STAS 3.0 frame (defensive; token inputs are always STAS 3.0 locking scripts).
  defp input_capability_flags(%{locking_script: %Script{} = script}) do
    parsed = Reader.read_locking_script(Script.to_binary(script))

    with %{script_type: :stas3, stas3: %{flags: flags}} when not is_nil(flags) <- parsed,
         {:ok, %ScriptFlags{} = decoded} <- ScriptFlags.decode(flags) do
      decoded
    else
      _ -> nil
    end
  end

  defp input_capability_flags(_), do: nil

  # Overwrite a destination's four capability-flag fields with `flags`.
  defp put_capability_flags(dest, %ScriptFlags{} = flags) do
    %{
      dest
      | freezable: flags.freezable,
        confiscatable: flags.confiscatable,
        nft: flags.nft,
        augmentable: flags.augmentable
    }
  end

  # Full capability flags for a destination (spec §15). STAS 3.0 flags are
  # immutable across a spend, so the caller sets each output's flags to match
  # its input; the builder encodes all four bits and selects the engine
  # revision (0.0.11 when NFT/AUGMENTABLE is set, else 0.0.9).
  defp dest_flags(dest) do
    %ScriptFlags{
      freezable: Map.get(dest, :freezable, false),
      confiscatable: Map.get(dest, :confiscatable, false),
      nft: Map.get(dest, :nft, false),
      augmentable: Map.get(dest, :augmentable, false)
    }
  end

  # ── §6.4 / §15.2 augmentation directive ──────────────────────────────

  @doc """
  Verify that a produced token output satisfies the augmentation covenant
  (spec §6.4 / §15.2) for a spent input.

  The `build_stas3_base_tx` transfer path *auto-appends* the directive so its
  output is covenant-correct by construction; use this to check a spend built
  some other way. If `input_locking_script` carries an active augmentation
  directive — an NFT + AUGMENTABLE frame whose `var2` is `{:augment, data}` —
  then `output_locking_script` MUST end with the directive data.
  """
  @spec verify_augment_directive_appended(binary(), binary()) ::
          :ok | {:error, :directive_not_appended}
  def verify_augment_directive_appended(input_locking_script, output_locking_script)
      when is_binary(input_locking_script) and is_binary(output_locking_script) do
    case augment_directive_for_script(input_locking_script) do
      {:ok, data} ->
        if binary_suffix?(output_locking_script, data),
          do: :ok,
          else: {:error, :directive_not_appended}

      :none ->
        :ok
    end
  end

  # The active augmentation directive carried by a spend's inputs, if any:
  # `data` when a consumed NFT+AUGMENTABLE input's var2 is `{:augment, data}`,
  # else nil. NFT frames are single-input, so at most one is ever active.
  defp active_augment_directive(token_inputs) do
    Enum.find_value(token_inputs, nil, fn ti ->
      case augment_directive_for_script(Script.to_binary(ti.locking_script)) do
        {:ok, data} -> data
        :none -> nil
      end
    end)
  end

  # `{:ok, data}` when a locking script decodes as an NFT+AUGMENTABLE frame whose
  # var2 is an augmentation directive; `:none` otherwise (inert / absent).
  defp augment_directive_for_script(script_bin) do
    case Reader.read_locking_script(script_bin) do
      %{script_type: :stas3, stas3: %{flags: flags, action_data_parsed: {:augment, data}}} ->
        case ScriptFlags.decode(flags) do
          {:ok, %ScriptFlags{nft: true, augmentable: true}} -> {:ok, data}
          _ -> :none
        end

      _ ->
        :none
    end
  end

  # Apply the augmentation covenant to a transfer's outputs: append the active
  # directive data to the first (sole) token output. No-op unless this is a
  # plain transfer carrying an active directive.
  defp apply_augment_directive(outputs, config) do
    if Map.get(config, :spend_type) == :transfer do
      case active_augment_directive(config.token_inputs) do
        nil -> outputs
        data -> append_to_first_output(outputs, data)
      end
    else
      outputs
    end
  end

  defp append_to_first_output([first | rest], data) do
    {:ok, script} = Script.from_binary(Script.to_binary(first.locking_script) <> data)
    [%{first | locking_script: script} | rest]
  end

  defp append_to_first_output([], _data), do: []

  defp binary_suffix?(bin, suffix) do
    s = byte_size(suffix)
    b = byte_size(bin)
    b >= s and binary_part(bin, b - s, s) == suffix
  end

  # Run a per-input validator across every token input; halt on first failure.
  defp validate_all(token_inputs, validator) when is_function(validator, 1) do
    Enum.reduce_while(token_inputs, :ok, fn ti, :ok ->
      case validator.(ti) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # Spec §15: how the §15.1 one-output and §15.2 directive-append covenants
  # interact with the swap (spendType 1) and confiscation (spendType 3) paths is
  # not yet pinned, and those builders bypass the normal-transfer NFT guard.
  # Refuse NFT inputs conservatively rather than risk an on-chain-invalid tx.
  defp reject_nft_spend_path(token_inputs) do
    if Enum.any?(token_inputs, &Stas3Validate.nft?/1),
      do: {:error, :nft_spend_path_unsupported},
      else: :ok
  end

  # Validate swap inputs: exactly 2, none frozen
  defp validate_swap_inputs(token_inputs) do
    cond do
      length(token_inputs) != 2 ->
        {:error, Error.invalid_destination("swap requires exactly 2 token inputs")}

      # Spec §15: NFT behaviour on the atomic-swap path (spendType 1) is not yet
      # pinned; refuse NFT legs conservatively.
      Enum.any?(token_inputs, &Stas3Validate.nft?/1) ->
        {:error, :nft_spend_path_unsupported}

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

  # ────────────────────────────────────────────────────────────────────
  # STAS 3.0 v0.1 §8.1 / §9.5 — atomic-swap & merge piece-array trailing
  # parameters (Item H wiring).
  #
  # The actual encoder/parser lives in `BSV.Tokens.Script.Stas3Pieces`;
  # the factory exposes wrappers so callers building swap or merge
  # transactions can append the spec-required trailing block to the
  # unlocking script AFTER `Stas3Template.sign/3` has produced the
  # signed authz prefix. We do NOT modify the existing 61-byte
  # non-recursive paths — both paths remain valid input/output of the
  # parser/encoder.
  # ────────────────────────────────────────────────────────────────────

  @doc """
  Build the txType=1 atomic-swap trailing-parameter block per spec §9.5.

  Wraps `BSV.Tokens.Script.Stas3Pieces.encode_atomic_swap_pieces/3`.

  Returns the raw bytes:
      counterparty_script_push ‖ piece_count_byte ‖ piece_array

  Append this binary to a STAS 3.0 swap unlocking script (after the
  authz block) when constructing a txType=1 transaction.
  """
  @spec build_atomic_swap_trailing(binary(), binary(), [non_neg_integer()]) ::
          {:ok, binary()} | {:error, term()}
  def build_atomic_swap_trailing(counterparty_locking_script, preceding_tx, asset_output_indices) do
    Stas3Pieces.encode_atomic_swap_pieces(
      counterparty_locking_script,
      preceding_tx,
      asset_output_indices
    )
  end

  @doc """
  Build the txType=2..7 merge trailing-parameter block per spec §8.1.

  Wraps `BSV.Tokens.Script.Stas3Pieces.encode_merge_pieces/3`.

  `piece_count` MUST be in `2..7` and equal `length(asset_output_indices)`.
  """
  @spec build_merge_trailing(2..7, binary(), [non_neg_integer()]) ::
          {:ok, binary()} | {:error, term()}
  def build_merge_trailing(piece_count, preceding_tx, asset_output_indices) do
    Stas3Pieces.encode_merge_pieces(piece_count, preceding_tx, asset_output_indices)
  end

  @doc """
  Parse a previously-encoded trailing parameter block.

  Wraps `BSV.Tokens.Script.Stas3Pieces.parse/2`.
  """
  @spec parse_trailing(binary(), 1..7) ::
          {:ok, map()} | {:error, term()}
  def parse_trailing(bin, tx_type), do: Stas3Pieces.parse(bin, tx_type)
end
