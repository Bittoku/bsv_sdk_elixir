defmodule BSV.Tokens.Factory.Stas3.WitnessBuilder do
  @moduledoc """
  Build a `BSV.Tokens.Stas3UnlockWitness` (spec §7 slots 1-20) for a single
  STAS 3.0 input that the factory layer is about to sign.

  The factory walks the partially-built transaction and asks this module to
  derive the witness for each STAS 3.0 input. The witness is then attached to
  the unlock template via `BSV.Tokens.Template.Stas3.with_witness/2` so that
  `Stas3Template.sign/3` produces an unlocking script of the form
  `witness_bytes ‖ authz_bytes`.

  ## Slot derivation rules

    * Slots 1-12 (`stas_outputs`): walk `tx.outputs` in order, take the first
      four whose script type is `:stas3`. Reject if more than 4 are present.
      For each, extract `%{amount, owner_pkh, var2}` from the parsed
      `Stas3Fields`. `var2` is the raw `action_data_raw` push payload.
    * Slots 13-14 (`change`): the first non-STAS output whose script type is
      `:p2pkh` or `:p2mpkh`. If absent, leave `change = nil`.
    * Slot 15 (`note_data`): the trailing OP_RETURN output's payload. Absent
      → nil.
    * Slots 16-17 (`funding_input`): identified by `funding_input_index` if
      provided, else the first non-STAS input. Stores `txid` and `vout`.
    * Slot 18 (`tx_type`): caller-supplied (atom or 0..7 byte).
    * Slot 19 (`sighash_preimage`): BIP-143 preimage for this input as
      computed via `BSV.Transaction.Sighash.calc_preimage/5`.
    * Slot 20 (`spend_type`): caller-supplied (atom or 1..4 byte).
  """

  alias BSV.Script
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, Sighash}
  alias BSV.Tokens.Script.{Reader, ParsedScript, Stas3Fields}
  alias BSV.Tokens.Stas3UnlockWitness

  @typedoc "STAS 3.0 spend type used in slot 20."
  @type spend_type :: :transfer | :freeze_unfreeze | :confiscation | :swap_cancellation

  @typedoc "STAS 3.0 tx type used in slot 18 — atom form or wire byte."
  @type tx_type :: atom() | 0..7

  @doc """
  Derive a `Stas3UnlockWitness` for the input at `input_index` in `tx`.

  Returns `{:ok, witness}` or `{:error, reason}`.

  Reasons:

    * `{:too_many_stas_outputs, n}` — more than 4 STAS outputs in `tx`,
      which the spec §7 witness cannot represent.
    * `:input_index_out_of_range`
    * `:missing_source_output` — the input has no `source_output` set.
    * any error returned by `BSV.Transaction.Sighash.calc_preimage/5`.
  """
  @spec derive_witness_for_input(
          Transaction.t(),
          non_neg_integer(),
          nil | non_neg_integer(),
          spend_type(),
          tx_type(),
          non_neg_integer()
        ) :: {:ok, Stas3UnlockWitness.t()} | {:error, term()}
  def derive_witness_for_input(
        %Transaction{} = tx,
        input_index,
        funding_input_index,
        spend_type,
        tx_type,
        sighash_flag
      )
      when is_integer(input_index) and input_index >= 0 and is_integer(sighash_flag) do
    cond do
      input_index >= length(tx.inputs) ->
        {:error, :input_index_out_of_range}

      true ->
        with {:ok, parsed_outputs} <- {:ok, parse_outputs(tx.outputs)},
             {:ok, stas_outputs} <- collect_stas_outputs(parsed_outputs),
             {:ok, preimage} <- compute_preimage(tx, input_index, sighash_flag) do
          change = collect_change(parsed_outputs)
          note_data = collect_note_data(parsed_outputs)
          funding_input = collect_funding_input(tx, parsed_outputs, funding_input_index)

          {:ok,
           %Stas3UnlockWitness{
             stas_outputs: stas_outputs,
             change: change,
             note_data: note_data,
             funding_input: funding_input,
             tx_type: tx_type,
             sighash_preimage: preimage,
             spend_type: spend_type
           }}
        end
    end
  end

  # ── output parsing ────────────────────────────────────────────────────

  # Annotate each output with its parsed locking-script summary so we only
  # parse once per output.
  defp parse_outputs(outputs) do
    Enum.map(outputs, fn %Output{} = out ->
      bin = Script.to_binary(out.locking_script)
      parsed = Reader.read_locking_script(bin)
      {out, parsed}
    end)
  end

  defp collect_stas_outputs(parsed_outputs) do
    stas =
      parsed_outputs
      |> Enum.filter(fn {_out, parsed} -> stas3?(parsed) end)
      |> Enum.map(fn {out, parsed} ->
        %Stas3Fields{owner: owner, action_data_raw: var2_raw} = parsed.stas3
        %{amount: out.satoshis, owner_pkh: owner, var2: var2_raw || <<>>}
      end)

    cond do
      length(stas) > 4 -> {:error, {:too_many_stas_outputs, length(stas)}}
      true -> {:ok, stas}
    end
  end

  defp collect_change(parsed_outputs) do
    parsed_outputs
    |> Enum.find_value(fn {out, parsed} ->
      cond do
        parsed.script_type == :p2pkh ->
          %{amount: out.satoshis, addr_pkh: extract_p2pkh_pkh(out)}

        parsed.script_type == :p2mpkh ->
          %{amount: out.satoshis, addr_pkh: extract_p2mpkh_mpkh(out)}

        true ->
          nil
      end
    end)
  end

  defp collect_note_data(parsed_outputs) do
    parsed_outputs
    |> Enum.reverse()
    |> Enum.find_value(fn {out, parsed} ->
      if parsed.script_type == :op_return,
        do: extract_op_return_payload(out),
        else: nil
    end)
  end

  defp collect_funding_input(%Transaction{inputs: inputs}, _parsed_outputs, idx)
       when is_integer(idx) do
    case Enum.at(inputs, idx) do
      %Input{source_txid: txid, source_tx_out_index: vout} when is_binary(txid) ->
        %{txid: txid, vout: vout}

      _ ->
        nil
    end
  end

  defp collect_funding_input(%Transaction{inputs: inputs}, _parsed_outputs, nil) do
    inputs
    |> Enum.find(fn %Input{} = inp ->
      case inp.source_output do
        %Output{locking_script: %Script{} = ls} ->
          parsed = Reader.read_locking_script(Script.to_binary(ls))
          parsed.script_type != :stas3

        _ ->
          true
      end
    end)
    |> case do
      nil -> nil
      %Input{source_txid: txid, source_tx_out_index: vout} -> %{txid: txid, vout: vout}
    end
  end

  # ── sighash preimage ─────────────────────────────────────────────────

  defp compute_preimage(%Transaction{} = tx, input_index, sighash_flag) do
    input = Enum.at(tx.inputs, input_index)

    case input do
      %Input{source_output: %Output{locking_script: %Script{} = ls, satoshis: sats}} ->
        Sighash.calc_preimage(tx, input_index, Script.to_binary(ls), sighash_flag, sats)

      _ ->
        {:error, :missing_source_output}
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────

  defp stas3?(%ParsedScript{script_type: :stas3, stas3: %Stas3Fields{}}), do: true
  defp stas3?(_), do: false

  # P2PKH locking script: 76 a9 14 <20B> 88 ac
  defp extract_p2pkh_pkh(%Output{locking_script: %Script{} = ls}) do
    case Script.to_binary(ls) do
      <<0x76, 0xA9, 0x14, pkh::binary-size(20), 0x88, 0xAC>> -> pkh
      _ -> <<0::160>>
    end
  end

  # P2MPKH locking script per §10.2: starts with 76 a9 14 <MPKH:20B> ...
  defp extract_p2mpkh_mpkh(%Output{locking_script: %Script{} = ls}) do
    case Script.to_binary(ls) do
      <<0x76, 0xA9, 0x14, mpkh::binary-size(20), _rest::binary>> -> mpkh
      _ -> <<0::160>>
    end
  end

  # OP_RETURN payload: concatenation of pushed data items after the
  # OP_FALSE OP_RETURN prefix (or bare OP_RETURN for legacy form).
  defp extract_op_return_payload(%Output{locking_script: %Script{chunks: chunks}}) do
    payload =
      chunks
      |> Enum.drop_while(fn
        {:op, 0x00} -> true
        {:op, 0x6A} -> false
        {:data, <<>>} -> true
        _ -> false
      end)
      |> Enum.drop(1)
      |> Enum.reduce(<<>>, fn
        {:data, d}, acc -> acc <> d
        _, acc -> acc
      end)

    case payload do
      <<>> -> nil
      bytes -> bytes
    end
  end
end
