defmodule BSV.Tokens.Lineage do
  @moduledoc """
  Off-chain lineage validator for STAS tokens.

  Walks the ancestor chain of a token UTXO back to the genesis (contract)
  transaction, verifying that every hop is a legitimate STAS token transfer
  or issuance.

  ## Usage

      validator = BSV.Tokens.Lineage.new(contract_txid, redemption_pkh)
      {:ok, validator} = BSV.Tokens.Lineage.validate(validator, utxo_txid, vout, tx_fetcher_fn)

  The `tx_fetcher_fn` is a function `(txid_binary -> {:ok, raw_tx} | {:error, reason})`.

  ## Security Notice — Trust Model

  This validator verifies the **chain of txids and script types** back to genesis,
  and confirms that `sha256d(raw_tx) == expected_txid` for each hop. However, it
  does **not** verify transaction signatures. It trusts the `tx_fetcher` to return
  authentic transaction data.

  If the `tx_fetcher` is backed by an untrusted source, an attacker could supply
  fabricated transactions with valid txid hashes but forged scripts/outputs. For
  maximum security, combine lineage validation with SPV proof verification (Merkle
  path against a trusted block header) to confirm each transaction was actually mined.
  """

  alias BSV.{Crypto, Transaction}
  alias BSV.Tokens.Script.Reader

  @max_chain_depth 10_000

  @type t :: %__MODULE__{
          validated: MapSet.t(binary()),
          contract_txid: <<_::256>>,
          redemption_pkh: <<_::160>>
        }

  defstruct [:contract_txid, :redemption_pkh, validated: MapSet.new()]

  @doc """
  Create a new lineage validator.

  The contract TX is pre-validated (it is the trust anchor).
  """
  @spec new(<<_::256>>, <<_::160>>) :: t()
  def new(<<contract_txid::binary-size(32)>>, <<redemption_pkh::binary-size(20)>>) do
    %__MODULE__{
      contract_txid: contract_txid,
      redemption_pkh: redemption_pkh,
      validated: MapSet.new([contract_txid])
    }
  end

  @doc """
  Validate a token UTXO's lineage back to the genesis transaction.

  **Note:** Only the first input of each transaction is followed during ancestor
  traversal. Multi-input token merges are not fully validated — only the lineage
  through input 0 is checked.

  The `tx_fetcher` is a function `(txid :: binary -> {:ok, raw_tx} | {:error, reason})`.

  Returns `{:ok, updated_validator}` on success.
  """
  @spec validate(t(), <<_::256>>, non_neg_integer(), (binary() -> {:ok, binary()} | {:error, term()})) ::
          {:ok, t()} | {:error, term()}
  def validate(%__MODULE__{} = validator, utxo_txid, vout, tx_fetcher)
      when is_binary(utxo_txid) and is_integer(vout) and is_function(tx_fetcher, 1) do
    do_validate(validator, utxo_txid, vout, tx_fetcher, 0)
  end

  @doc "Check whether a specific txid has already been validated."
  @spec is_validated?(t(), binary()) :: boolean()
  def is_validated?(%__MODULE__{validated: validated}, txid), do: MapSet.member?(validated, txid)

  @doc "Return the number of txids that have been validated so far."
  @spec validated_count(t()) :: non_neg_integer()
  def validated_count(%__MODULE__{validated: validated}), do: MapSet.size(validated)

  # ---- Private ----

  defp do_validate(validator, current_txid, current_vout, tx_fetcher, depth) do
    if MapSet.member?(validator.validated, current_txid) do
      {:ok, validator}
    else
      if depth >= @max_chain_depth do
        {:error, "lineage chain exceeds maximum depth (#{@max_chain_depth})"}
      else
        with {:ok, raw_tx} <- tx_fetcher.(current_txid),
             :ok <- verify_txid(raw_tx, current_txid),
             {:ok, tx, _rest} <- Transaction.from_binary(raw_tx),
             {:ok, output} <- get_output(tx, current_txid, current_vout) do
          script_bin = BSV.Script.to_binary(output.locking_script)
          parsed = Reader.read_locking_script(script_bin)

          case parsed.script_type do
            type when type in [:stas, :stas_btg] ->
              handle_stas_hop(validator, tx, current_txid, parsed, tx_fetcher, depth)

            :p2pkh ->
              handle_p2pkh_hop(validator, tx, current_txid, tx_fetcher, depth)

            other ->
              {:error, "unexpected script type #{inspect(other)} at vout #{current_vout} in tx #{Base.encode16(current_txid, case: :lower)}"}
          end
        end
      end
    end
  end

  defp verify_txid(raw_tx, expected_txid) do
    computed = Crypto.sha256d(raw_tx)

    if computed == expected_txid do
      :ok
    else
      {:error, "fetched TX hash mismatch: expected #{Base.encode16(expected_txid, case: :lower)}, got #{Base.encode16(computed, case: :lower)}"}
    end
  end

  defp get_output(tx, txid, vout) do
    case Enum.at(tx.outputs, vout) do
      nil -> {:error, "vout #{vout} out of range in tx #{Base.encode16(txid, case: :lower)}"}
      output -> {:ok, output}
    end
  end

  defp handle_stas_hop(validator, tx, current_txid, parsed, tx_fetcher, depth) do
    stas_fields = parsed.stas

    if stas_fields.redemption_hash != validator.redemption_pkh do
      {:error, "redemption PKH mismatch in tx #{Base.encode16(current_txid, case: :lower)}"}
    else
      validator = %{validator | validated: MapSet.put(validator.validated, current_txid)}

      case tx.inputs do
        [] ->
          {:error, "transaction has no inputs"}

        [first_input | _] ->
          do_validate(
            validator,
            first_input.source_txid,
            first_input.source_tx_out_index,
            tx_fetcher,
            depth + 1
          )
      end
    end
  end

  defp handle_p2pkh_hop(validator, tx, current_txid, tx_fetcher, depth) do
    case tx.inputs do
      [] ->
        {:error, "transaction has no inputs"}

      inputs ->
        references_contract =
          Enum.any?(inputs, fn input -> input.source_txid == validator.contract_txid end)

        validator = %{validator | validated: MapSet.put(validator.validated, current_txid)}

        if references_contract do
          {:ok, validator}
        else
          first_input = hd(inputs)

          do_validate(
            validator,
            first_input.source_txid,
            first_input.source_tx_out_index,
            tx_fetcher,
            depth + 1
          )
        end
    end
  end
end
