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

  @spec new() :: t()
  def new, do: %__MODULE__{}

  @spec from_binary(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def from_binary(<<satoshis::little-64, rest::binary>>) do
    with {:ok, {script_len, rest}} <- VarInt.decode(rest),
         <<script_bin::binary-size(script_len), rest::binary>> <- rest,
         {:ok, script} <- Script.from_binary(script_bin) do
      {:ok, %__MODULE__{satoshis: satoshis, locking_script: script}, rest}
    else
      _ -> {:error, :invalid_output}
    end
  end

  def from_binary(_), do: {:error, :insufficient_data}

  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{satoshis: satoshis, locking_script: script}) do
    script_bin = Script.to_binary(script)
    <<satoshis::little-64>> <> VarInt.encode(byte_size(script_bin)) <> script_bin
  end

  @spec locking_script_hex(t()) :: String.t()
  def locking_script_hex(%__MODULE__{locking_script: script}), do: Script.to_hex(script)
end
