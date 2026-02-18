defmodule BSV.Transaction.Output do
  @moduledoc "Bitcoin transaction output."

  alias BSV.Script
  alias BSV.VarInt

  @type t :: %__MODULE__{
          satoshis: non_neg_integer(),
          locking_script: Script.t(),
          change: boolean()
        }

  defstruct satoshis: 0,
            locking_script: %Script{},
            change: false

  @doc "Create a new empty output with default values."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  # 21 million BTC in satoshis
  @max_satoshis 21_000_000 * 100_000_000

  @doc "Parse an output from raw binary. Returns `{:ok, output, remaining_bytes}` on success."
  @spec from_binary(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def from_binary(<<satoshis::little-64, rest::binary>>) do
    if satoshis > @max_satoshis do
      {:error, :satoshi_value_out_of_range}
    else
      with {:ok, {script_len, rest}} <- VarInt.decode(rest),
           <<script_bin::binary-size(script_len), rest::binary>> <- rest,
           {:ok, script} <- Script.from_binary(script_bin) do
        {:ok, %__MODULE__{satoshis: satoshis, locking_script: script}, rest}
      else
        _ -> {:error, :invalid_output}
      end
    end
  end

  def from_binary(_), do: {:error, :insufficient_data}

  @doc "Serialize the output to raw binary (wire format)."
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{satoshis: satoshis, locking_script: script}) do
    script_bin = Script.to_binary(script)
    <<satoshis::little-64>> <> VarInt.encode(byte_size(script_bin)) <> script_bin
  end

  @doc "Return the locking script as a hex string."
  @spec locking_script_hex(t()) :: String.t()
  def locking_script_hex(%__MODULE__{locking_script: script}), do: Script.to_hex(script)
end
