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
end
