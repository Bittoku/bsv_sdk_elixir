defmodule BSV.Transaction do
  @moduledoc "Bitcoin SV transaction."

  alias BSV.{Crypto, VarInt, Script}
  alias BSV.Transaction.{Input, Output, Sighash}

  @type t :: %__MODULE__{
          version: non_neg_integer(),
          inputs: [Input.t()],
          outputs: [Output.t()],
          lock_time: non_neg_integer()
        }

  defstruct version: 1,
            inputs: [],
            outputs: [],
            lock_time: 0

  @spec new() :: t()
  def new, do: %__MODULE__{}

  @spec from_binary(binary()) :: {:ok, t()} | {:error, term()}
  def from_binary(<<version::little-32, rest::binary>>) do
    with {:ok, inputs, rest} <- parse_inputs(rest),
         {:ok, outputs, rest} <- parse_outputs(rest) do
      case rest do
        <<lock_time::little-32>> ->
          {:ok,
           %__MODULE__{version: version, inputs: inputs, outputs: outputs, lock_time: lock_time}}

        <<lock_time::little-32, _extra::binary>> ->
          {:ok,
           %__MODULE__{version: version, inputs: inputs, outputs: outputs, lock_time: lock_time}}

        _ ->
          {:error, :invalid_lock_time}
      end
    end
  end

  def from_binary(_), do: {:error, :insufficient_data}

  @spec from_hex(String.t()) :: {:ok, t()} | {:error, term()}
  def from_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> from_binary(bin)
      :error -> {:error, :invalid_hex}
    end
  end

  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = tx) do
    inputs_bin =
      VarInt.encode(length(tx.inputs)) <>
        Enum.reduce(tx.inputs, <<>>, fn inp, acc -> acc <> Input.to_binary(inp) end)

    outputs_bin =
      VarInt.encode(length(tx.outputs)) <>
        Enum.reduce(tx.outputs, <<>>, fn out, acc -> acc <> Output.to_binary(out) end)

    <<tx.version::little-32>> <> inputs_bin <> outputs_bin <> <<tx.lock_time::little-32>>
  end

  @spec to_hex(t()) :: String.t()
  def to_hex(%__MODULE__{} = tx), do: tx |> to_binary() |> Base.encode16(case: :lower)

  @spec tx_id(t()) :: <<_::256>>
  def tx_id(%__MODULE__{} = tx), do: Crypto.sha256d(to_binary(tx))

  @spec tx_id_hex(t()) :: String.t()
  def tx_id_hex(%__MODULE__{} = tx) do
    tx
    |> tx_id()
    |> :binary.bin_to_list()
    |> Enum.reverse()
    |> :binary.list_to_bin()
    |> Base.encode16(case: :lower)
  end

  @spec add_input(t(), Input.t()) :: t()
  def add_input(%__MODULE__{} = tx, %Input{} = input) do
    %{tx | inputs: tx.inputs ++ [input]}
  end

  @spec add_output(t(), Output.t()) :: t()
  def add_output(%__MODULE__{} = tx, %Output{} = output) do
    %{tx | outputs: tx.outputs ++ [output]}
  end

  @spec add_input_from(t(), String.t(), non_neg_integer(), String.t(), non_neg_integer()) ::
          {:ok, t()} | {:error, term()}
  def add_input_from(%__MODULE__{} = tx, prev_tx_id_hex, vout, prev_locking_script_hex, satoshis) do
    with {:ok, txid_bytes} <- decode_txid_hex(prev_tx_id_hex),
         {:ok, locking_script} <- Script.from_hex(prev_locking_script_hex) do
      input = %Input{
        source_txid: txid_bytes,
        source_tx_out_index: vout,
        source_output: %Output{satoshis: satoshis, locking_script: locking_script}
      }

      {:ok, add_input(tx, input)}
    end
  end

  @spec total_input_satoshis(t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def total_input_satoshis(%__MODULE__{inputs: inputs}) do
    Enum.reduce_while(inputs, {:ok, 0}, fn input, {:ok, acc} ->
      case Input.source_satoshis(input) do
        nil -> {:halt, {:error, :missing_source_output}}
        s -> {:cont, {:ok, acc + s}}
      end
    end)
  end

  @spec total_output_satoshis(t()) :: non_neg_integer()
  def total_output_satoshis(%__MODULE__{outputs: outputs}) do
    Enum.reduce(outputs, 0, fn %Output{satoshis: s}, acc -> acc + s end)
  end

  @spec is_coinbase?(t()) :: boolean()
  def is_coinbase?(%__MODULE__{inputs: [%Input{source_txid: txid, source_tx_out_index: vout}]}) do
    txid == <<0::256>> and vout == 0xFFFFFFFF
  end

  def is_coinbase?(_), do: false

  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{} = tx), do: byte_size(to_binary(tx))

  @spec calc_input_signature_hash(t(), non_neg_integer(), non_neg_integer()) ::
          {:ok, <<_::256>>} | {:error, term()}
  def calc_input_signature_hash(%__MODULE__{} = tx, input_index, sighash_flag) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        script_bin = Script.to_binary(source_output.locking_script)
        Sighash.signature_hash(tx, input_index, script_bin, sighash_flag, source_output.satoshis)
    end
  end

  # Private helpers

  defp parse_inputs(bin) do
    with {:ok, {count, rest}} <- VarInt.decode(bin) do
      parse_n(rest, count, &Input.from_binary/1, [])
    end
  end

  defp parse_outputs(bin) do
    with {:ok, {count, rest}} <- VarInt.decode(bin) do
      parse_n(rest, count, &Output.from_binary/1, [])
    end
  end

  defp parse_n(rest, 0, _parser, acc), do: {:ok, Enum.reverse(acc), rest}

  defp parse_n(rest, n, parser, acc) do
    case parser.(rest) do
      {:ok, item, rest2} -> parse_n(rest2, n - 1, parser, [item | acc])
      {:error, _} = err -> err
    end
  end

  defp decode_txid_hex(hex) when byte_size(hex) == 64 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} -> {:ok, :binary.list_to_bin(Enum.reverse(:binary.bin_to_list(bytes)))}
      :error -> {:error, :invalid_hex}
    end
  end

  defp decode_txid_hex(_), do: {:error, :invalid_txid_hex}
end
