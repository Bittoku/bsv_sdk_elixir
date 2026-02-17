defmodule BSV.Transaction.Builder do
  @moduledoc "Pipe-friendly transaction builder."

  alias BSV.Transaction
  alias BSV.Transaction.{Output, P2PKH}
  alias BSV.Script

  @doc "Create a new empty transaction."
  @spec new() :: Transaction.t()
  def new, do: Transaction.new()

  @doc "Add an input from hex-encoded txid, vout, locking script hex, and satoshi amount. Raises on error."
  @spec add_input(Transaction.t(), String.t(), non_neg_integer(), String.t(), non_neg_integer()) ::
          Transaction.t()
  def add_input(%Transaction{} = tx, prev_txid_hex, vout, locking_script_hex, satoshis) do
    case Transaction.add_input_from(tx, prev_txid_hex, vout, locking_script_hex, satoshis) do
      {:ok, tx2} -> tx2
      {:error, reason} -> raise ArgumentError, "add_input failed: #{inspect(reason)}"
    end
  end

  @doc "Add a P2PKH output paying to the given Base58Check address. Raises on invalid address."
  @spec add_p2pkh_output(Transaction.t(), String.t(), non_neg_integer()) :: Transaction.t()
  def add_p2pkh_output(%Transaction{} = tx, address_string, satoshis) do
    case P2PKH.lock(address_string) do
      {:ok, script} ->
        Transaction.add_output(tx, %Output{satoshis: satoshis, locking_script: script})

      {:error, reason} ->
        raise ArgumentError, "add_p2pkh_output failed: #{inspect(reason)}"
    end
  end

  @doc "Add an OP_RETURN output containing the given data pushes (0 satoshis)."
  @spec add_op_return_output(Transaction.t(), [binary()]) :: Transaction.t()
  def add_op_return_output(%Transaction{} = tx, data_list) when is_list(data_list) do
    script = Script.op_return(data_list)
    Transaction.add_output(tx, %Output{satoshis: 0, locking_script: script})
  end

  @doc "Append a pre-built output to the transaction."
  @spec add_output(Transaction.t(), Output.t()) :: Transaction.t()
  def add_output(%Transaction{} = tx, %Output{} = output) do
    Transaction.add_output(tx, output)
  end

  @doc "Sign a single input using the given signing template (e.g. `P2PKH`, `Stas`)."
  @spec sign_input(Transaction.t(), non_neg_integer(), struct()) ::
          {:ok, Transaction.t()} | {:error, term()}
  def sign_input(%Transaction{} = tx, input_index, template) do
    module = template.__struct__

    case module.sign(template, tx, input_index) do
      {:ok, unlocking_script} ->
        input = Enum.at(tx.inputs, input_index)
        updated_input = %{input | unlocking_script: unlocking_script}
        updated_inputs = List.replace_at(tx.inputs, input_index, updated_input)
        {:ok, %{tx | inputs: updated_inputs}}

      {:error, _} = err ->
        err
    end
  end

  @doc "Sign all inputs using the same signing template."
  @spec sign_all_inputs(Transaction.t(), struct()) ::
          {:ok, Transaction.t()} | {:error, term()}
  def sign_all_inputs(%Transaction{} = tx, template) do
    Enum.reduce_while(0..(length(tx.inputs) - 1), {:ok, tx}, fn i, {:ok, acc_tx} ->
      case sign_input(acc_tx, i, template) do
        {:ok, new_tx} -> {:cont, {:ok, new_tx}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  @doc "Validate and finalize the transaction. Returns error if inputs or outputs are missing."
  @spec build(Transaction.t()) :: {:ok, Transaction.t()} | {:error, term()}
  def build(%Transaction{} = tx) do
    cond do
      Enum.empty?(tx.inputs) and not Transaction.is_coinbase?(tx) ->
        {:error, :no_inputs}

      Enum.empty?(tx.outputs) ->
        {:error, :no_outputs}

      true ->
        {:ok, tx}
    end
  end
end
