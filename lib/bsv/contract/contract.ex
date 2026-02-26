defmodule BSV.Contract do
  @moduledoc """
  A behaviour and pipeline DSL for building Bitcoin locking and unlocking scripts.

  Contracts define `locking_script/2` and optionally `unlocking_script/2` callbacks
  that build scripts using a chainable pipeline of opcode and data push helpers.

  ## Example

      defmodule MyP2PKH do
        use BSV.Contract

        @impl true
        def locking_script(ctx, %{pubkey_hash: pkh}) do
          ctx
          |> op_dup()
          |> op_hash160()
          |> push(pkh)
          |> op_equalverify()
          |> op_checksig()
        end
      end

      script = MyP2PKH.lock(1000, %{pubkey_hash: <<...>>}) |> BSV.Contract.to_script()

  ## Using contracts with TxBuilder

  Contracts return `BSV.Contract.t()` structs that carry the module, function,
  and parameters needed to build scripts lazily.
  """

  alias BSV.Script
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output}

  defstruct ctx: nil, mfa: nil, opts: [], subject: nil, script: %Script{}

  @typedoc "Contract struct"
  @type t :: %__MODULE__{
          ctx: ctx() | nil,
          mfa: {module(), atom(), list()},
          opts: keyword(),
          subject: non_neg_integer() | map() | nil,
          script: Script.t()
        }

  @typedoc "Transaction context: {transaction, input_index}"
  @type ctx :: {BSV.Transaction.t(), non_neg_integer()}

  @doc "Callback to generate the locking script."
  @callback locking_script(t(), map()) :: t()

  @doc "Callback to generate the unlocking script."
  @callback unlocking_script(t(), map()) :: t()

  @optional_callbacks unlocking_script: 2

  defmacro __using__(_opts) do
    quote do
      @behaviour BSV.Contract
      import BSV.Contract.Helpers
      import BSV.Contract.VarIntHelpers

      @doc "Create a locking contract with the given satoshis and parameters."
      @spec lock(non_neg_integer(), map(), keyword()) :: BSV.Contract.t()
      def lock(satoshis, %{} = params, opts \\ []) do
        %BSV.Contract{
          mfa: {__MODULE__, :locking_script, [params]},
          opts: opts,
          subject: satoshis
        }
      end

      @doc "Create an unlocking contract with the given UTXO info and parameters."
      @spec unlock(map(), map(), keyword()) :: BSV.Contract.t()
      def unlock(%{} = utxo_info, %{} = params, opts \\ []) do
        %BSV.Contract{
          mfa: {__MODULE__, :unlocking_script, [params]},
          opts: opts,
          subject: utxo_info
        }
      end
    end
  end

  @doc """
  Attach a transaction context to the contract for signature generation.
  """
  @spec put_ctx(t(), ctx()) :: t()
  def put_ctx(%__MODULE__{} = contract, {tx, vin}) when is_integer(vin) do
    %{contract | ctx: {tx, vin}}
  end

  @doc """
  Push a value (opcode byte, data binary, or integer) onto the contract script.
  """
  @spec script_push(t(), Script.chunk()) :: t()
  def script_push(%__MODULE__{script: script} = contract, chunk) do
    %{contract | script: %{script | chunks: script.chunks ++ [chunk]}}
  end

  @doc """
  Compile the contract and return the built `BSV.Script`.
  """
  @spec to_script(t()) :: Script.t()
  def to_script(%__MODULE__{mfa: {mod, fun, args}} = contract) do
    %{script: script} = apply(mod, fun, [contract | args])
    script
  end

  @doc """
  Compile the contract and return the script as a binary.
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = contract) do
    contract |> to_script() |> Script.to_binary()
  end

  @doc """
  Return the size in bytes of the compiled script.
  """
  @spec script_size(t()) :: non_neg_integer()
  def script_size(%__MODULE__{} = contract) do
    byte_size(to_binary(contract))
  end

  @doc """
  Compile the locking contract and return a `BSV.Transaction.Output`.
  """
  @spec to_txout(t()) :: Output.t()
  def to_txout(%__MODULE__{subject: satoshis} = contract) when is_integer(satoshis) do
    %Output{satoshis: satoshis, locking_script: to_script(contract)}
  end

  @doc """
  Compile the unlocking contract and return a `BSV.Transaction.Input`.

  The contract subject must be a map with `:source_txid`, `:source_tx_out_index`,
  and optionally `:source_output` and `:sequence_number`.
  """
  @spec to_txin(t()) :: Input.t()
  def to_txin(%__MODULE__{subject: utxo, opts: opts} = contract) when is_map(utxo) do
    sequence = Keyword.get(opts, :sequence, 0xFFFFFFFF)
    script = to_script(contract)

    %Input{
      source_txid: Map.get(utxo, :source_txid, <<0::256>>),
      source_tx_out_index: Map.get(utxo, :source_tx_out_index, 0),
      unlocking_script: script,
      sequence_number: sequence,
      source_output: Map.get(utxo, :source_output)
    }
  end

  @doc """
  Simulate a contract lock/unlock cycle and verify it against the script interpreter.

  Creates a fake locking transaction, then spends it with the unlocking params,
  and runs the combined script through `BSV.Script.Interpreter`.

  Returns `{:ok, true}` on success, `{:error, reason}` on failure.

  ## Example

      {:ok, true} = Contract.simulate(
        BSV.Contract.P2PKH,
        %{pubkey_hash: pkh},
        %{signature: sig, pubkey: pubkey}
      )
  """
  @spec simulate(module(), map(), map(), keyword()) :: {:ok, boolean()} | {:error, term()}
  def simulate(mod, lock_params, unlock_params, opts \\ []) do
    satoshis = Keyword.get(opts, :satoshis, 1000)

    # Build the locking output
    lock_contract = apply(mod, :lock, [satoshis, lock_params])
    locking_script = to_script(lock_contract)

    # Create a fake funding tx
    funding_txid = BSV.Crypto.sha256d("funding_tx_for_simulate")

    source_output = %Output{satoshis: satoshis, locking_script: locking_script}

    utxo = %{
      source_txid: funding_txid,
      source_tx_out_index: 0,
      source_output: source_output
    }

    # Build the unlocking contract (no context yet)
    unlock_contract = apply(mod, :unlock, [utxo, unlock_params])

    # Build a spending tx with one input + one output
    spending_tx = %Transaction{
      version: 1,
      inputs: [
        %Input{
          source_txid: funding_txid,
          source_tx_out_index: 0,
          unlocking_script: %Script{},
          sequence_number: 0xFFFFFFFF,
          source_output: source_output
        }
      ],
      outputs: [%Output{satoshis: satoshis, locking_script: %Script{}}],
      lock_time: 0
    }

    # Attach tx context and compile
    unlock_with_ctx = put_ctx(unlock_contract, {spending_tx, 0})
    unlocking_script = to_script(unlock_with_ctx)

    # Update the spending tx with the real unlocking script
    spending_tx = %{
      spending_tx
      | inputs: [%{hd(spending_tx.inputs) | unlocking_script: unlocking_script}]
    }

    # Build sighash function for the interpreter
    sighash_fn = fn sig_der, pubkey_bin, sighash_type ->
      locking_bin = Script.to_binary(locking_script)

      case BSV.Transaction.Sighash.signature_hash(
             spending_tx,
             0,
             locking_bin,
             sighash_type,
             satoshis
           ) do
        {:ok, hash} ->
          # Verify DER signature against pubkey
          try do
            result =
              :crypto.verify(:ecdsa, :sha256, {:digest, hash}, sig_der, [pubkey_bin, :secp256k1])

            {:ok, result}
          rescue
            _ -> {:ok, false}
          end

        {:error, _} = err ->
          err
      end
    end

    # Run through interpreter
    case BSV.Script.Interpreter.verify(
           unlocking_script,
           locking_script,
           sighash_fn: sighash_fn
         ) do
      :ok -> {:ok, true}
      {:error, _} = err -> err
    end
  end
end
