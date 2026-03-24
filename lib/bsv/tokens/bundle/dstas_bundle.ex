defmodule BSV.Tokens.Bundle.DstasBundle do
  @moduledoc """
  DSTAS Bundle Factory — automatic merge/split/transfer transaction planning.

  Given callback functions for UTXO retrieval, transaction lookup, and script
  construction, the factory automatically plans sequences of merge/split/transfer
  transactions to fulfill multi-recipient payouts.

  ## How It Works

  1. **UTXO Selection** — selects the minimum set of STAS UTXOs that cover the
     required amount (exact match preferred, else smallest-first accumulation)
  2. **Merge Tree** — if multiple UTXOs selected, builds pairwise merge
     transactions to consolidate into a single UTXO. Inserts "transfer refresh"
     levels every 3 merge levels to prevent excessive script depth.
  3. **Transfer Planning** — splits the consolidated UTXO across recipients,
     up to 3 per intermediate tx (with STAS change), up to 4 in the final tx.
  4. **Fee Chaining** — a single funding UTXO is chained through all transactions;
     each tx's fee change output feeds the next tx's fee input.

  ## Callback Functions

  The struct holds five callback functions:

  - `get_stas_utxo_set` — `(min_satoshis) -> [utxo]` returns available STAS UTXOs
  - `get_funding_utxo` — `(request) -> utxo` returns a fee-paying UTXO
  - `get_transactions` — `([txid_hex]) -> %{txid_hex => Transaction.t()}` lookups
  - `build_locking_params` — `(args) -> DstasOutputParams.t()` constructs output params
  - `build_unlocking_script` — `(args) -> {:ok, Script.t()}` signs/unlocks inputs

  ## UTXO Map Structure

  Each UTXO in callbacks is a map with keys:
  - `:txid` — 32-byte binary txid (internal byte order)
  - `:txid_hex` — hex string txid (display order, for transaction lookups)
  - `:vout` — output index
  - `:satoshis` — satoshi amount
  - `:locking_script` — `Script.t()` locking script
  """

  alias BSV.{Script, Transaction}
  alias BSV.Transaction.{Input, Output}
  alias BSV.Tokens.Error

  # Default fee rate in satoshis per kilobyte
  @default_fee_rate 500

  @type utxo :: %{
          txid: binary(),
          txid_hex: String.t(),
          vout: non_neg_integer(),
          satoshis: non_neg_integer(),
          locking_script: Script.t()
        }

  @type funding_request :: %{
          utxo_ids_to_spend: [String.t()],
          estimated_fee_satoshis: non_neg_integer(),
          transactions_count: non_neg_integer()
        }

  @type locking_params_args :: %{
          from_utxo: utxo(),
          recipient: recipient(),
          spend_type: spend_type(),
          is_freeze_like: boolean(),
          output_index: non_neg_integer(),
          output_count: non_neg_integer(),
          is_change: boolean()
        }

  @type unlocking_args :: %{
          tx: Transaction.t(),
          input_index: non_neg_integer(),
          utxo: utxo(),
          spend_type: spend_type(),
          is_freeze_like: boolean(),
          is_merge: boolean()
        }

  @type recipient :: %{
          m: pos_integer(),
          addresses: [String.t()]
        }

  @type transfer_output :: %{
          recipient: recipient(),
          satoshis: non_neg_integer()
        }

  @type spend_type :: :transfer | :freeze | :unfreeze | :swap | :confiscation

  @type bundle_result ::
          {:ok, %{transactions: [String.t()], fee_satoshis: non_neg_integer()}}
          | {:ok, %{message: String.t(), fee_satoshis: 0}}

  @type t :: %__MODULE__{
          get_stas_utxo_set: (non_neg_integer() -> [utxo()]),
          get_funding_utxo: (funding_request() -> utxo()),
          get_transactions: ([String.t()] -> %{String.t() => Transaction.t()}),
          build_locking_params: (locking_params_args() -> BSV.Tokens.DstasOutputParams.t()),
          build_unlocking_script: (unlocking_args() -> {:ok, Script.t()}),
          stas_wallet: map(),
          fee_wallet: map(),
          fee_rate: non_neg_integer()
        }

  defstruct [
    :get_stas_utxo_set,
    :get_funding_utxo,
    :get_transactions,
    :build_locking_params,
    :build_unlocking_script,
    :stas_wallet,
    :fee_wallet,
    fee_rate: @default_fee_rate
  ]

  # ── Public API ──────────────────────────────────────────────────────────────

  @doc """
  Plan and build a multi-recipient transfer bundle.

  Takes a list of `outputs` (each with `:recipient` and `:satoshis`), an optional
  `:spend_type` (default `:transfer`), and optional `:note` (list of binaries for
  OP_RETURN, attached only to the final transaction).

  Returns `{:ok, %{transactions: [hex], fee_satoshis: int}}` on success, or
  `{:ok, %{message: "Insufficient ...", fee_satoshis: 0}}` if balance is too low.
  Raises on invalid inputs (empty outputs, zero satoshis).
  """
  @spec transfer(t(), %{
          outputs: [transfer_output()],
          spend_type: spend_type(),
          note: [binary()] | nil
        }) :: bundle_result()
  def transfer(%__MODULE__{} = bundle, request) do
    outputs = Map.fetch!(request, :outputs)
    spend_type = Map.get(request, :spend_type, :transfer)
    note = Map.get(request, :note)

    # Validate outputs
    if outputs == [] do
      raise Error.invalid_destination("at least one transfer output is required")
    end

    Enum.each(outputs, fn output ->
      if !is_integer(output.satoshis) or output.satoshis <= 0 do
        raise Error.invalid_destination(
                "transfer output satoshis must be a positive integer, got #{output.satoshis}"
              )
      end
    end)

    amount_satoshis = Enum.sum(Enum.map(outputs, & &1.satoshis))

    # Fetch and sort STAS UTXOs
    stas_utxo_set =
      bundle.get_stas_utxo_set.(amount_satoshis)
      |> Enum.sort_by(& &1.satoshis)

    available_satoshis = Enum.sum(Enum.map(stas_utxo_set, & &1.satoshis))

    if available_satoshis < amount_satoshis do
      {:ok, %{message: "Insufficient STAS tokens balance", fee_satoshis: 0}}
    else
      stas_utxos = select_stas_utxos(stas_utxo_set, amount_satoshis)

      build_bundle_with_resolved_funding(
        bundle,
        stas_utxos,
        amount_satoshis,
        outputs,
        spend_type,
        note
      )
    end
  end

  @doc "Create a single-recipient transfer bundle."
  @spec create_transfer_bundle(t(), non_neg_integer(), recipient(), [binary()] | nil) ::
          bundle_result()
  def create_transfer_bundle(bundle, amount, recipient, note \\ nil) do
    transfer(bundle, %{
      outputs: [%{recipient: recipient, satoshis: amount}],
      spend_type: :transfer,
      note: note
    })
  end

  @doc "Create a freeze bundle (sets spend type to :freeze)."
  @spec create_freeze_bundle(t(), non_neg_integer(), recipient(), [binary()] | nil) ::
          bundle_result()
  def create_freeze_bundle(bundle, amount, recipient, note \\ nil) do
    transfer(bundle, %{
      outputs: [%{recipient: recipient, satoshis: amount}],
      spend_type: :freeze,
      note: note
    })
  end

  @doc "Create an unfreeze bundle (sets spend type to :unfreeze)."
  @spec create_unfreeze_bundle(t(), non_neg_integer(), recipient(), [binary()] | nil) ::
          bundle_result()
  def create_unfreeze_bundle(bundle, amount, recipient, note \\ nil) do
    transfer(bundle, %{
      outputs: [%{recipient: recipient, satoshis: amount}],
      spend_type: :unfreeze,
      note: note
    })
  end

  @doc "Create a swap bundle."
  @spec create_swap_bundle(t(), non_neg_integer(), recipient(), [binary()] | nil) ::
          bundle_result()
  def create_swap_bundle(bundle, amount, recipient, note \\ nil) do
    create_bundle(bundle, amount, recipient, :swap, note)
  end

  @doc "Create a confiscation bundle."
  @spec create_confiscation_bundle(t(), non_neg_integer(), recipient(), [binary()] | nil) ::
          bundle_result()
  def create_confiscation_bundle(bundle, amount, recipient, note \\ nil) do
    create_bundle(bundle, amount, recipient, :confiscation, note)
  end

  @doc """
  Generic bundle creation for spend types that bypass `transfer/2` validation
  (swap, confiscation). These use `get_stas_utxo_set` directly.
  """
  @spec create_bundle(t(), non_neg_integer(), recipient(), spend_type(), [binary()] | nil) ::
          bundle_result()
  def create_bundle(bundle, amount, recipient, spend_type, note \\ nil) do
    stas_utxo_set =
      bundle.get_stas_utxo_set.(amount)
      |> Enum.sort_by(& &1.satoshis)

    available = Enum.sum(Enum.map(stas_utxo_set, & &1.satoshis))

    if available < amount do
      {:ok, %{message: "Insufficient STAS tokens balance", fee_satoshis: 0}}
    else
      stas_utxos = select_stas_utxos(stas_utxo_set, amount)

      build_bundle_with_resolved_funding(
        bundle,
        stas_utxos,
        amount,
        [%{recipient: recipient, satoshis: amount}],
        spend_type,
        note
      )
    end
  end

  # ── UTXO Selection ──────────────────────────────────────────────────────────

  @doc false
  def select_stas_utxos(sorted_utxos, satoshis) do
    # Prefer exact match
    exact = Enum.find(sorted_utxos, fn u -> u.satoshis == satoshis end)

    if exact do
      [exact]
    else
      # Accumulate smallest-first
      {accumulated, result} =
        Enum.reduce_while(sorted_utxos, {0, []}, fn utxo, {acc, list} ->
          new_acc = acc + utxo.satoshis
          new_list = list ++ [utxo]

          if new_acc >= satoshis do
            {:halt, {new_acc, new_list}}
          else
            {:cont, {new_acc, new_list}}
          end
        end)

      if accumulated >= satoshis do
        result
      else
        # Fallback: single UTXO >= amount
        fallback = Enum.find(sorted_utxos, fn u -> u.satoshis >= satoshis end)
        if fallback, do: [fallback], else: result
      end
    end
  end

  # ── Fee Estimation ──────────────────────────────────────────────────────────

  @doc false
  def estimate_transactions_count(stas_input_count, outputs_count) do
    estimate_merge_tx_count(stas_input_count) +
      estimate_transfer_tx_count(outputs_count)
  end

  @doc false
  def estimate_merge_tx_count(stas_input_count) when stas_input_count <= 1, do: 0

  def estimate_merge_tx_count(stas_input_count) do
    do_estimate_merge(stas_input_count, 0, 0)
  end

  defp do_estimate_merge(1, _levels_before_transfer, tx_count), do: tx_count

  defp do_estimate_merge(current_count, 3, tx_count) do
    # Insert transfer-refresh level
    do_estimate_merge(current_count, 0, tx_count + current_count)
  end

  defp do_estimate_merge(current_count, levels_before_transfer, tx_count) do
    merges = div(current_count, 2)
    remainder = rem(current_count, 2)
    do_estimate_merge(merges + remainder, levels_before_transfer + 1, tx_count + merges)
  end

  @doc false
  def estimate_transfer_tx_count(outputs_count) do
    max(1, ceil_div(outputs_count - 1, 3))
  end

  @doc false
  def estimate_bundle_fee_upper_bound(tx_count, stas_input_count, outputs_count, fee_rate) do
    max(
      1200,
      ceil(
        (tx_count * 1400 + stas_input_count * 500 + outputs_count * 160 + 500) *
          fee_rate / 1000 * 1.5
      )
    )
  end

  # ── Bundle Construction ─────────────────────────────────────────────────────

  defp build_bundle_with_resolved_funding(
         bundle,
         stas_utxos,
         amount_satoshis,
         outputs,
         spend_type,
         note
       ) do
    utxo_ids = Enum.map(stas_utxos, fn u -> "#{u.txid_hex}:#{u.vout}" end)
    tx_count = estimate_transactions_count(length(stas_utxos), length(outputs))

    initial_fee_estimate =
      estimate_bundle_fee_upper_bound(
        tx_count,
        length(stas_utxos),
        length(outputs),
        bundle.fee_rate
      )

    funding_utxo =
      bundle.get_funding_utxo.(%{
        utxo_ids_to_spend: utxo_ids,
        estimated_fee_satoshis: initial_fee_estimate,
        transactions_count: tx_count
      })

    try do
      do_create_transfer_bundle(
        bundle,
        [],
        stas_utxos,
        amount_satoshis,
        funding_utxo,
        outputs,
        spend_type,
        note
      )
    rescue
      e in [Error] ->
        if insufficient_fee_error?(e) do
          # Retry with more generous fee estimate
          fallback_fee = ceil(initial_fee_estimate * 1.5) + 200

          fallback_funding =
            bundle.get_funding_utxo.(%{
              utxo_ids_to_spend: utxo_ids,
              estimated_fee_satoshis: fallback_fee,
              transactions_count: tx_count
            })

          do_create_transfer_bundle(
            bundle,
            [],
            stas_utxos,
            amount_satoshis,
            fallback_funding,
            outputs,
            spend_type,
            note
          )
        else
          reraise e, __STACKTRACE__
        end
    end
  end

  defp insufficient_fee_error?(%Error{type: :insufficient_funds}), do: true
  defp insufficient_fee_error?(_), do: false

  defp do_create_transfer_bundle(
         bundle,
         transactions,
         stas_utxos,
         satoshis_to_send,
         fee_utxo,
         outputs,
         spend_type,
         note
       ) do
    {merge_txs, merged_stas_utxo, merged_fee_utxo} =
      merge_stas_transactions(bundle, stas_utxos, satoshis_to_send, fee_utxo)

    transactions = transactions ++ (merge_txs || [])

    {transfer_txs, final_fee_utxo} =
      build_transfer_plan_transactions(
        bundle,
        merged_stas_utxo,
        merged_fee_utxo,
        outputs,
        spend_type,
        note
      )

    transactions = transactions ++ transfer_txs
    paid_fee = fee_utxo.satoshis - final_fee_utxo.satoshis

    {:ok, %{transactions: transactions, fee_satoshis: paid_fee}}
  end

  # ── Merge Tree ──────────────────────────────────────────────────────────────

  defp merge_stas_transactions(_bundle, [single_utxo], _satoshis, fee_utxo) do
    {nil, single_utxo, fee_utxo}
  end

  defp merge_stas_transactions(bundle, stas_utxos, satoshis, fee_utxo) do
    # Fetch source transactions for full OutPoint reconstruction
    txid_hexes = stas_utxos |> Enum.map(& &1.txid_hex) |> Enum.uniq()
    source_txs = bundle.get_transactions.(txid_hexes)

    # Build initial level with full UTXO info from source transactions
    initial_level =
      Enum.map(stas_utxos, fn utxo ->
        case Map.get(source_txs, utxo.txid_hex) do
          nil ->
            # If source tx not found, use the utxo as-is
            utxo

          tx ->
            output = Enum.at(tx.outputs, utxo.vout)

            %{
              txid: Transaction.tx_id(tx),
              txid_hex: Transaction.tx_id_hex(tx),
              vout: utxo.vout,
              satoshis: output.satoshis,
              locking_script: output.locking_script
            }
        end
      end)

    merge_txs = []
    current_fee_utxo = fee_utxo

    do_merge_loop(bundle, initial_level, satoshis, merge_txs, current_fee_utxo, 0)
  end

  defp do_merge_loop(_bundle, [single], _satoshis, merge_txs, fee_utxo, _levels) do
    {merge_txs, single, fee_utxo}
  end

  defp do_merge_loop(bundle, current_level, satoshis, merge_txs, fee_utxo, 3) do
    # Transfer-refresh level: transfer each UTXO to self to reset script depth
    {new_level, new_merge_txs, new_fee_utxo} =
      do_transfer_refresh(bundle, current_level, merge_txs, fee_utxo)

    do_merge_loop(bundle, new_level, satoshis, new_merge_txs, new_fee_utxo, 0)
  end

  defp do_merge_loop(bundle, current_level, satoshis, merge_txs, fee_utxo, levels_before) do
    merge_count = div(length(current_level), 2)
    remainder = rem(length(current_level), 2)

    # Odd UTXO carries forward
    new_level =
      if remainder != 0, do: [List.last(current_level)], else: []

    pairs = Enum.chunk_every(Enum.take(current_level, merge_count * 2), 2)

    {new_level, new_merge_txs, new_fee_utxo} =
      Enum.reduce(
        Enum.with_index(pairs),
        {new_level, merge_txs, fee_utxo},
        fn {[utxo1, utxo2], idx}, {level, txs, current_fee} ->
          last_merge = merge_count == 1 and remainder == 0 and idx == 0
          input_satoshis = utxo1.satoshis + utxo2.satoshis

          # On the final merge, split if total > required
          merge_outputs =
            if last_merge and input_satoshis != satoshis do
              [
                %{
                  recipient: self_recipient(bundle),
                  satoshis: satoshis,
                  is_change: false
                },
                %{
                  recipient: self_recipient(bundle),
                  satoshis: input_satoshis - satoshis,
                  is_change: true
                }
              ]
            else
              [
                %{
                  recipient: self_recipient(bundle),
                  satoshis: input_satoshis,
                  is_change: false
                }
              ]
            end

          {tx_hex, tx} =
            build_dstas_tx(bundle, %{
              stas_utxos: [utxo1, utxo2],
              fee_utxo: current_fee,
              destinations: merge_outputs,
              spend_type: :merge,
              is_merge: true,
              note: nil
            })

          stas_out = get_stas_outpoint(tx)
          fee_out = get_fee_outpoint(tx)

          {level ++ [stas_out], txs ++ [tx_hex], fee_out}
        end
      )

    do_merge_loop(bundle, new_level, satoshis, new_merge_txs, new_fee_utxo, levels_before + 1)
  end

  defp do_transfer_refresh(bundle, current_level, merge_txs, fee_utxo) do
    Enum.reduce(current_level, {[], merge_txs, fee_utxo}, fn utxo, {level, txs, current_fee} ->
      outputs = [
        %{
          recipient: self_recipient(bundle),
          satoshis: utxo.satoshis,
          is_change: false
        }
      ]

      {tx_hex, tx} =
        build_dstas_tx(bundle, %{
          stas_utxos: [utxo],
          fee_utxo: current_fee,
          destinations: outputs,
          spend_type: :transfer,
          is_merge: false,
          note: nil
        })

      stas_out = get_stas_outpoint(tx)
      fee_out = get_fee_outpoint(tx)

      {level ++ [stas_out], txs ++ [tx_hex], fee_out}
    end)
  end

  # ── Transfer Planning ───────────────────────────────────────────────────────

  defp build_transfer_plan_transactions(
         bundle,
         stas_utxo,
         fee_utxo,
         outputs,
         spend_type,
         note
       ) do
    remaining_total = Enum.sum(Enum.map(outputs, & &1.satoshis))

    do_transfer_plan(bundle, stas_utxo, fee_utxo, outputs, 0, remaining_total, spend_type, note, [])
  end

  defp do_transfer_plan(
         _bundle,
         _stas_utxo,
         fee_utxo,
         outputs,
         cursor,
         _remaining,
         _spend_type,
         _note,
         transactions
       )
       when cursor >= length(outputs) do
    {transactions, fee_utxo}
  end

  defp do_transfer_plan(
         bundle,
         current_stas,
         current_fee,
         outputs,
         cursor,
         remaining_total,
         spend_type,
         note,
         transactions
       ) do
    remaining_count = length(outputs) - cursor
    is_final = remaining_count <= 4

    transfer_outputs =
      if is_final do
        Enum.slice(outputs, cursor, remaining_count)
      else
        Enum.slice(outputs, cursor, 3)
      end

    sent_satoshis = Enum.sum(Enum.map(transfer_outputs, & &1.satoshis))

    # Build tx outputs with optional STAS change
    tx_outputs =
      Enum.map(transfer_outputs, fn out ->
        %{recipient: out.recipient, satoshis: out.satoshis, is_change: false}
      end)

    tx_outputs =
      if !is_final do
        tx_outputs ++
          [
            %{
              recipient: self_recipient(bundle),
              satoshis: current_stas.satoshis - sent_satoshis,
              is_change: true
            }
          ]
      else
        tx_outputs
      end

    {tx_hex, tx} =
      build_dstas_tx(bundle, %{
        stas_utxos: [current_stas],
        fee_utxo: current_fee,
        destinations: tx_outputs,
        spend_type: spend_type,
        is_merge: false,
        note: if(is_final, do: note, else: nil)
      })

    new_fee = get_fee_outpoint(tx)
    transactions = transactions ++ [tx_hex]

    if is_final do
      {transactions, new_fee}
    else
      # Get change output for next iteration
      change_idx = length(tx_outputs) - 1
      new_stas = outpoint_from_tx(tx, change_idx)

      do_transfer_plan(
        bundle,
        new_stas,
        new_fee,
        outputs,
        cursor + length(transfer_outputs),
        remaining_total - sent_satoshis,
        spend_type,
        note,
        transactions
      )
    end
  end

  # ── Transaction Building ────────────────────────────────────────────────────

  defp build_dstas_tx(bundle, params) do
    %{
      stas_utxos: stas_utxos,
      fee_utxo: fee_utxo,
      destinations: destinations,
      spend_type: spend_type,
      is_merge: is_merge,
      note: note
    } = params

    is_freeze_like = spend_type in [:freeze, :unfreeze]

    # Map spend_type to the DstasSpendType used by base factory
    _wire_spend_type = map_spend_type(spend_type)

    # Build STAS inputs
    stas_inputs =
      Enum.map(stas_utxos, fn utxo ->
        %Input{
          source_txid: utxo.txid,
          source_tx_out_index: utxo.vout,
          source_output: %Output{
            satoshis: utxo.satoshis,
            locking_script: utxo.locking_script
          }
        }
      end)

    # Build fee input
    fee_input = %Input{
      source_txid: fee_utxo.txid,
      source_tx_out_index: fee_utxo.vout,
      source_output: %Output{
        satoshis: fee_utxo.satoshis,
        locking_script: fee_utxo.locking_script
      }
    }

    # Build DSTAS outputs via the locking params callback
    dstas_outputs =
      Enum.with_index(destinations)
      |> Enum.map(fn {dest, idx} ->
        # Use the first STAS input as the source for locking params
        source_utxo = List.first(stas_utxos)

        output_params =
          bundle.build_locking_params.(%{
            from_utxo: source_utxo,
            recipient: dest.recipient,
            spend_type: spend_type,
            is_freeze_like: is_freeze_like,
            output_index: idx,
            output_count: length(destinations),
            is_change: Map.get(dest, :is_change, false)
          })

        # Build the locking script from output params
        {:ok, script} =
          BSV.Tokens.Script.DstasBuilder.build_dstas_locking_script(
            output_params.owner_pkh,
            output_params.redemption_pkh,
            output_params.action_data,
            output_params.frozen,
            output_params.freezable,
            output_params.service_fields,
            output_params.optional_data
          )

        %Output{satoshis: dest.satoshis, locking_script: script}
      end)

    # Build fee change output
    fee_output_idx = length(dstas_outputs)

    # Note output (OP_RETURN) — only for final tx
    note_output =
      if note do
        [%Output{satoshis: 0, locking_script: Script.op_return(note)}]
      else
        []
      end

    # Fee change output placeholder — will adjust after fee calc
    fee_address = bundle.fee_wallet.address
    {:ok, fee_change_script} = BSV.Script.Address.to_script(fee_address)
    fee_change_output = %Output{satoshis: fee_utxo.satoshis, locking_script: fee_change_script, change: true}

    # Assemble outputs: DSTAS outputs, fee change, then note
    all_outputs =
      dstas_outputs ++
        [fee_change_output] ++
        note_output

    # Build unsigned transaction
    tx = %Transaction{
      inputs: stas_inputs ++ [fee_input],
      outputs: all_outputs
    }

    # Estimate fee
    est_size = estimate_tx_size(tx)
    fee = ceil_div(est_size * bundle.fee_rate, 1000)

    if fee >= fee_utxo.satoshis do
      raise Error.insufficient_funds(fee, fee_utxo.satoshis)
    end

    # Set fee change amount
    fee_change = fee_utxo.satoshis - fee

    tx =
      put_in(
        tx,
        [Access.key(:outputs), Access.at(fee_output_idx)],
        %{fee_change_output | satoshis: fee_change}
      )

    # Sign STAS inputs via callback
    tx =
      Enum.reduce(Enum.with_index(stas_utxos), tx, fn {utxo, idx}, acc_tx ->
        {:ok, unlocking_script} =
          bundle.build_unlocking_script.(%{
            tx: acc_tx,
            input_index: idx,
            utxo: utxo,
            spend_type: spend_type,
            is_freeze_like: is_freeze_like,
            is_merge: is_merge
          })

        set_unlocking_script(acc_tx, idx, unlocking_script)
      end)

    # Sign fee input with P2PKH
    fee_input_idx = length(stas_utxos)

    tx =
      case bundle.fee_wallet do
        %{private_key: pk} ->
          unlocker = BSV.Transaction.P2PKH.unlock(pk)

          case BSV.Transaction.P2PKH.sign(unlocker, tx, fee_input_idx) do
            {:ok, sig} -> set_unlocking_script(tx, fee_input_idx, sig)
            {:error, reason} -> raise "Fee signing failed: #{inspect(reason)}"
          end

        _ ->
          tx
      end

    tx_hex = Transaction.to_hex(tx)
    {tx_hex, tx}
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp self_recipient(bundle) do
    %{m: 1, addresses: [bundle.stas_wallet.address]}
  end

  defp map_spend_type(:transfer), do: :transfer
  defp map_spend_type(:freeze), do: :freeze_unfreeze
  defp map_spend_type(:unfreeze), do: :freeze_unfreeze
  defp map_spend_type(:swap), do: :swap_cancellation
  defp map_spend_type(:confiscation), do: :confiscation
  defp map_spend_type(:merge), do: :transfer

  defp set_unlocking_script(tx, index, script) do
    inputs =
      List.update_at(tx.inputs, index, fn inp ->
        %{inp | unlocking_script: script}
      end)

    %{tx | inputs: inputs}
  end

  defp estimate_tx_size(tx) do
    # Version(4) + VarInt(inputs) + inputs + VarInt(outputs) + outputs + locktime(4)
    base = 4 + 1 + 1 + 4

    inputs_size =
      Enum.reduce(tx.inputs, 0, fn inp, acc ->
        unlocking_size =
          case inp.unlocking_script do
            nil -> 106
            %Script{} = s -> byte_size(Script.to_binary(s))
            _ -> 106
          end

        acc + 32 + 4 + 1 + unlocking_size + 4
      end)

    outputs_size =
      Enum.reduce(tx.outputs, 0, fn out, acc ->
        script_size = byte_size(Script.to_binary(out.locking_script))
        acc + 8 + 1 + script_size
      end)

    base + inputs_size + outputs_size
  end

  @doc false
  def get_stas_outpoint(tx) do
    # Find the first non-P2PKH, non-OP_RETURN output (i.e., the STAS output)
    {output, idx} =
      tx.outputs
      |> Enum.with_index()
      |> Enum.find(fn {out, _idx} ->
        not Script.is_p2pkh?(out.locking_script) and
          not Script.is_op_return?(out.locking_script) and
          not out.change
      end) || raise "STAS output not found"

    %{
      txid: Transaction.tx_id(tx),
      txid_hex: Transaction.tx_id_hex(tx),
      vout: idx,
      satoshis: output.satoshis,
      locking_script: output.locking_script
    }
  end

  @doc false
  def get_fee_outpoint(tx) do
    # Find the last P2PKH output (fee change) — search from end
    {output, idx} =
      tx.outputs
      |> Enum.with_index()
      |> Enum.reverse()
      |> Enum.find(fn {out, _idx} ->
        Script.is_p2pkh?(out.locking_script)
      end) || raise "Fee output not found"

    %{
      txid: Transaction.tx_id(tx),
      txid_hex: Transaction.tx_id_hex(tx),
      vout: idx,
      satoshis: output.satoshis,
      locking_script: output.locking_script
    }
  end

  defp outpoint_from_tx(tx, vout) do
    output = Enum.at(tx.outputs, vout)

    %{
      txid: Transaction.tx_id(tx),
      txid_hex: Transaction.tx_id_hex(tx),
      vout: vout,
      satoshis: output.satoshis,
      locking_script: output.locking_script
    }
  end

  defp ceil_div(a, b) when b > 0 do
    div(a + b - 1, b)
  end
end
