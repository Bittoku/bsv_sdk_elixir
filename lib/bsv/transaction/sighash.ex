defmodule BSV.Transaction.Sighash do
  @moduledoc "BIP-143 style signature hash computation for BSV (with FORKID)."

  alias BSV.Crypto
  alias BSV.VarInt
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output}
  import Bitwise

  # @sighash_all 0x01
  @sighash_none 0x02
  @sighash_single 0x03
  @sighash_anyonecanpay 0x80
  # @sighash_forkid 0x40
  @sighash_mask 0x1F

  @doc "Compute the signature hash for an input."
  @spec signature_hash(
          Transaction.t(),
          non_neg_integer(),
          binary(),
          non_neg_integer(),
          non_neg_integer()
        ) ::
          {:ok, <<_::256>>} | {:error, term()}
  def signature_hash(tx, input_index, prev_output_script_bin, sighash_type, satoshis) do
    if band(sighash_type, 0x40) == 0 do
      {:error, :missing_forkid}
    else
    with {:ok, preimage} <-
           calc_preimage(tx, input_index, prev_output_script_bin, sighash_type, satoshis) do
      {:ok, Crypto.sha256d(preimage)}
    end
    end
  end

  @doc "Compute the BIP-143 preimage."
  @spec calc_preimage(
          Transaction.t(),
          non_neg_integer(),
          binary(),
          non_neg_integer(),
          non_neg_integer()
        ) ::
          {:ok, binary()} | {:error, term()}
  def calc_preimage(
        %Transaction{} = tx,
        input_index,
        prev_output_script_bin,
        sighash_type,
        satoshis
      ) do
    if band(sighash_type, 0x40) == 0 do
      {:error, :missing_forkid}
    else if input_index >= length(tx.inputs) do
      {:error, :input_index_out_of_range}
    else
      base_type = sighash_type |> band(@sighash_mask)
      anyone_can_pay = sighash_type |> band(@sighash_anyonecanpay) != 0

      input = Enum.at(tx.inputs, input_index)

      hash_prevouts =
        if anyone_can_pay, do: <<0::256>>, else: source_out_hash(tx)

      hash_sequence =
        if anyone_can_pay or base_type in [@sighash_single, @sighash_none],
          do: <<0::256>>,
          else: sequence_hash(tx)

      hash_outputs =
        cond do
          base_type == @sighash_none ->
            <<0::256>>

          base_type == @sighash_single and input_index < length(tx.outputs) ->
            outputs_hash(tx, input_index)

          base_type == @sighash_single ->
            <<0::256>>

          true ->
            outputs_hash(tx, :all)
        end

      script_code = VarInt.encode(byte_size(prev_output_script_bin)) <> prev_output_script_bin

      preimage =
        <<tx.version::little-32>> <>
          hash_prevouts <>
          hash_sequence <>
          <<input.source_txid::binary-size(32), input.source_tx_out_index::little-32>> <>
          script_code <>
          <<satoshis::little-64>> <>
          <<input.sequence_number::little-32>> <>
          hash_outputs <>
          <<tx.lock_time::little-32>> <>
          <<sighash_type::little-32>>

      {:ok, preimage}
    end
    end
  end

  defp source_out_hash(%Transaction{inputs: inputs}) do
    data =
      Enum.reduce(inputs, <<>>, fn %Input{} = inp, acc ->
        acc <> <<inp.source_txid::binary-size(32), inp.source_tx_out_index::little-32>>
      end)

    Crypto.sha256d(data)
  end

  defp sequence_hash(%Transaction{inputs: inputs}) do
    data =
      Enum.reduce(inputs, <<>>, fn %Input{} = inp, acc ->
        acc <> <<inp.sequence_number::little-32>>
      end)

    Crypto.sha256d(data)
  end

  defp outputs_hash(%Transaction{outputs: outputs}, :all) do
    data =
      Enum.reduce(outputs, <<>>, fn output, acc ->
        acc <> Output.to_binary(output)
      end)

    Crypto.sha256d(data)
  end

  defp outputs_hash(%Transaction{outputs: outputs}, index) when is_integer(index) do
    output = Enum.at(outputs, index)
    Crypto.sha256d(Output.to_binary(output))
  end
end
