defmodule BSV.Transaction.Input do
  @moduledoc "Bitcoin transaction input."

  alias BSV.Script
  alias BSV.VarInt
  alias BSV.Transaction.Output

  @type t :: %__MODULE__{
          source_txid: binary(),
          source_tx_out_index: non_neg_integer(),
          sequence_number: non_neg_integer(),
          unlocking_script: Script.t() | nil,
          source_output: Output.t() | nil
        }

  defstruct source_txid: <<0::256>>,
            source_tx_out_index: 0,
            sequence_number: 0xFFFFFFFF,
            unlocking_script: nil,
            source_output: nil

  @doc "Create a new empty input with default values."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc "Parse an input from raw binary. Returns `{:ok, input, remaining_bytes}` on success."
  @spec from_binary(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def from_binary(<<txid::binary-size(32), vout::little-32, rest::binary>>) do
    with {:ok, {script_len, rest}} <- VarInt.decode(rest),
         <<script_bin::binary-size(script_len), seq::little-32, rest::binary>> <- rest do
      script =
        if script_len == 0 do
          nil
        else
          case Script.from_binary(script_bin) do
            {:ok, s} -> s
            _ -> nil
          end
        end

      {:ok,
       %__MODULE__{
         source_txid: txid,
         source_tx_out_index: vout,
         sequence_number: seq,
         unlocking_script: script
       }, rest}
    else
      _ -> {:error, :invalid_input}
    end
  end

  def from_binary(_), do: {:error, :insufficient_data}

  @doc "Serialize the input to raw binary (wire format)."
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = input) do
    script_bin =
      if input.unlocking_script, do: Script.to_binary(input.unlocking_script), else: <<>>

    <<input.source_txid::binary-size(32), input.source_tx_out_index::little-32>> <>
      VarInt.encode(byte_size(script_bin)) <>
      script_bin <>
      <<input.sequence_number::little-32>>
  end

  @doc "Serialize the input with an empty unlocking script (for sighash computation)."
  @spec to_binary_cleared(t()) :: binary()
  def to_binary_cleared(%__MODULE__{} = input) do
    <<input.source_txid::binary-size(32), input.source_tx_out_index::little-32>> <>
      VarInt.encode(0) <>
      <<input.sequence_number::little-32>>
  end

  @doc "Get the satoshi value of the source output, or `nil` if not set."
  @spec source_satoshis(t()) :: non_neg_integer() | nil
  def source_satoshis(%__MODULE__{source_output: nil}), do: nil
  def source_satoshis(%__MODULE__{source_output: %Output{satoshis: s}}), do: s

  @doc "Get the locking script of the source output, or `nil` if not set."
  @spec source_locking_script(t()) :: Script.t() | nil
  def source_locking_script(%__MODULE__{source_output: nil}), do: nil
  def source_locking_script(%__MODULE__{source_output: %Output{locking_script: s}}), do: s
end
