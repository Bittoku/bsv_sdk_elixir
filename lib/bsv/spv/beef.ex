defmodule BSV.SPV.Beef do
  @moduledoc """
  BEEF (Background Evaluation Extended Format) transaction container.

  Supports BRC-64 (V1), BRC-96 (V2), and BRC-95 (Atomic BEEF) formats.
  """

  alias BSV.VarInt
  alias BSV.SPV.MerklePath
  alias BSV.Transaction

  @beef_v1 4_022_206_465
  @beef_v2 4_022_206_466
  @atomic_beef 0x01010101

  defmodule BeefTx do
    @moduledoc "A transaction within a BEEF container."
    defstruct [:data_format, :known_txid, :transaction, bump_index: 0]

    @type data_format :: :raw_tx | :raw_tx_and_bump | :txid_only
    @type t :: %__MODULE__{
            data_format: data_format(),
            known_txid: binary() | nil,
            transaction: Transaction.t() | nil,
            bump_index: non_neg_integer()
          }
  end

  @enforce_keys [:version]
  defstruct [:version, bumps: [], transactions: %{}]

  @type t :: %__MODULE__{
          version: non_neg_integer(),
          bumps: [MerklePath.t()],
          transactions: %{binary() => BeefTx.t()}
        }

  @doc "BEEF V1 version constant."
  def beef_v1, do: @beef_v1
  @doc "BEEF V2 version constant."
  def beef_v2, do: @beef_v2

  @doc "Parse a BEEF from a hex string."
  @spec from_hex(String.t()) :: {:ok, t()} | {:error, String.t()}
  def from_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> from_bytes(bin)
      :error -> {:error, "invalid hex"}
    end
  end

  @doc "Parse a BEEF from binary data."
  @spec from_bytes(binary()) :: {:ok, t()} | {:error, String.t()}
  def from_bytes(data) when byte_size(data) < 4, do: {:error, "data too short"}

  def from_bytes(<<@atomic_beef::little-32, _skip::binary-size(32), rest::binary>>) do
    parse_beef_body(rest)
  end

  def from_bytes(data), do: parse_beef_body(data)

  defp parse_beef_body(<<version::little-32, rest::binary>>) do
    if version != @beef_v1 and version != @beef_v2 do
      {:error, "invalid BEEF version: #{version}"}
    else
      with {:ok, bumps, rest2} <- read_bumps(rest),
           {:ok, txs, _rest3} <- read_transactions(rest2, version) do
        {:ok, %__MODULE__{version: version, bumps: bumps, transactions: txs}}
      end
    end
  end

  defp read_bumps(data) do
    {:ok, {count, rest}} = VarInt.decode(data)
    read_n_bumps(rest, count, [])
  end

  defp read_n_bumps(rest, 0, acc), do: {:ok, Enum.reverse(acc), rest}

  defp read_n_bumps(data, n, acc) do
    case MerklePath.from_bytes(data) do
      {:ok, mp} ->
        # Re-serialize to find consumed bytes
        _ = byte_size(MerklePath.to_bytes(mp)) - byte_size(VarInt.encode(mp.block_height))
        # Actually, we need a from_bytes that returns remaining. Simpler: re-parse with known size.
        # For now, re-serialize and skip that many bytes
        serialized = serialize_single_bump(mp)
        <<_::binary-size(byte_size(serialized)), rest::binary>> = data
        read_n_bumps(rest, n - 1, [mp | acc])

      error ->
        error
    end
  end

  defp serialize_single_bump(%MerklePath{} = mp) do
    # Serialize without the block_height varint prefix (it's part of the BUMP format)
    # Actually MerklePath.to_bytes includes block_height. The BEEF format includes
    # the full BUMP. So we just use to_bytes directly.
    MerklePath.to_bytes(mp)
  end

  defp read_transactions(data, version) do
    {:ok, {count, rest}} = VarInt.decode(data)

    if version == @beef_v1 do
      read_v1_transactions(rest, count, %{})
    else
      read_v2_transactions(rest, count, %{})
    end
  end

  defp read_v1_transactions(rest, 0, acc), do: {:ok, acc, rest}

  defp read_v1_transactions(data, n, acc) do
    case Transaction.from_binary(data) do
      {:ok, tx, rest} ->
        txid = Transaction.txid_binary(tx)

        # Check if there's a BUMP index after the tx
        {bump_index, has_bump, rest2} =
          if byte_size(rest) > 0 do
            <<flag::8, rest2::binary>> = rest
            if flag == 0x01 do
              {:ok, {idx, rest3}} = VarInt.decode(rest2)
              {idx, true, rest3}
            else
              {0, false, rest}
            end
          else
            {0, false, rest}
          end

        beef_tx = %BeefTx{
          data_format: if(has_bump, do: :raw_tx_and_bump, else: :raw_tx),
          transaction: tx,
          bump_index: bump_index
        }

        read_v1_transactions(rest2, n - 1, Map.put(acc, txid, beef_tx))

      {:error, reason} ->
        {:error, "reading transaction: #{reason}"}
    end
  end

  defp read_v2_transactions(rest, 0, acc), do: {:ok, acc, rest}

  defp read_v2_transactions(<<format_byte::8, rest::binary>>, n, acc) do
    case format_byte do
      2 ->
        # TxID only
        <<txid::binary-size(32), rest2::binary>> = rest
        beef_tx = %BeefTx{data_format: :txid_only, known_txid: txid}
        read_v2_transactions(rest2, n - 1, Map.put(acc, txid, beef_tx))

      1 ->
        # Raw TX + BUMP index
        {:ok, {bump_index, rest2}} = VarInt.decode(rest)

        case Transaction.from_binary(rest2) do
          {:ok, tx, rest3} ->
            txid = Transaction.txid_binary(tx)
            beef_tx = %BeefTx{data_format: :raw_tx_and_bump, transaction: tx, bump_index: bump_index}
            read_v2_transactions(rest3, n - 1, Map.put(acc, txid, beef_tx))

          {:error, reason} ->
            {:error, "reading transaction: #{reason}"}
        end

      0 ->
        # Raw TX only
        case Transaction.from_binary(rest) do
          {:ok, tx, rest2} ->
            txid = Transaction.txid_binary(tx)
            beef_tx = %BeefTx{data_format: :raw_tx, transaction: tx}
            read_v2_transactions(rest2, n - 1, Map.put(acc, txid, beef_tx))

          {:error, reason} ->
            {:error, "reading transaction: #{reason}"}
        end

      other ->
        {:error, "invalid data format: #{other}"}
    end
  end
end
