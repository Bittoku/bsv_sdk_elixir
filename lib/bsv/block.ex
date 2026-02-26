defmodule BSV.Block do
  @moduledoc """
  A Bitcoin block consisting of a `BSV.BlockHeader` and a list of transactions.

  Supports parsing from binary/hex, serialization, merkle root calculation,
  and validation.
  """

  alias BSV.{BlockHeader, Crypto, Transaction, VarInt}

  defstruct header: nil, txns: []

  @typedoc "Block struct"
  @type t :: %__MODULE__{
          header: BlockHeader.t(),
          txns: [Transaction.t()]
        }

  @doc """
  Parse a block from a binary.

  Returns `{:ok, block, rest}` or `{:error, reason}`.
  """
  @spec from_binary(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def from_binary(data) when is_binary(data) do
    with {:ok, header, rest} <- BlockHeader.from_binary(data),
         {:ok, txns, rest} <- parse_txns(rest) do
      {:ok, %__MODULE__{header: header, txns: txns}, rest}
    end
  end

  @doc """
  Parse a block from a hex-encoded string.
  """
  @spec from_hex(String.t()) :: {:ok, t()} | {:error, term()}
  def from_hex(hex) when is_binary(hex) do
    with {:ok, bin} <- safe_decode16(hex),
         {:ok, block, _rest} <- from_binary(bin) do
      {:ok, block}
    end
  end

  @doc """
  Serialize a block to binary.
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{header: header, txns: txns}) do
    header_bin = BlockHeader.to_binary(header)
    count = VarInt.encode(length(txns))

    txns_bin =
      Enum.reduce(txns, <<>>, fn tx, acc ->
        acc <> Transaction.to_binary(tx)
      end)

    header_bin <> count <> txns_bin
  end

  @doc """
  Serialize a block to a hex-encoded string.
  """
  @spec to_hex(t()) :: String.t()
  def to_hex(%__MODULE__{} = block), do: block |> to_binary() |> Base.encode16(case: :lower)

  @doc """
  Calculate the merkle root from the block's transactions.
  """
  @spec calc_merkle_root(t()) :: <<_::256>>
  def calc_merkle_root(%__MODULE__{txns: txns}) do
    txns
    |> Enum.map(&Transaction.tx_id/1)
    |> merkle_hash()
  end

  @doc """
  Validate that the calculated merkle root matches the header's merkle root.
  """
  @spec valid_merkle_root?(t()) :: boolean()
  def valid_merkle_root?(%__MODULE__{header: header} = block) do
    calc_merkle_root(block) == header.merkle_root
  end

  @doc """
  Return the block hash (delegates to `BlockHeader.hash/1`).
  """
  @spec hash(t()) :: <<_::256>>
  def hash(%__MODULE__{header: header}), do: BlockHeader.hash(header)

  @doc """
  Return the block hash as a display-order hex string.
  """
  @spec hash_hex(t()) :: String.t()
  def hash_hex(%__MODULE__{header: header}), do: BlockHeader.hash_hex(header)

  @doc """
  Return the number of transactions in the block.
  """
  @spec tx_count(t()) :: non_neg_integer()
  def tx_count(%__MODULE__{txns: txns}), do: length(txns)

  @doc """
  Check if a block is a genesis block (prev_hash is all zeros).
  """
  @spec genesis?(t()) :: boolean()
  def genesis?(%__MODULE__{header: %{prev_hash: prev_hash}}) do
    prev_hash == <<0::256>>
  end

  # -- Private --

  defp parse_txns(data) do
    with {:ok, {count, rest}} <- VarInt.decode(data) do
      parse_n_txns(rest, count, [])
    end
  end

  defp parse_n_txns(rest, 0, acc), do: {:ok, Enum.reverse(acc), rest}

  defp parse_n_txns(data, n, acc) do
    case Transaction.from_binary(data) do
      {:ok, tx, rest} -> parse_n_txns(rest, n - 1, [tx | acc])
      {:error, _} = err -> err
    end
  end

  defp merkle_hash([root]), do: root
  defp merkle_hash([]), do: <<0::256>>

  defp merkle_hash(hashes) do
    hashes
    |> pad_odd()
    |> Enum.chunk_every(2)
    |> Enum.map(fn [a, b] -> Crypto.sha256d(a <> b) end)
    |> merkle_hash()
  end

  defp pad_odd(list) do
    if rem(length(list), 2) == 1, do: list ++ [List.last(list)], else: list
  end

  defp safe_decode16(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :invalid_hex}
    end
  end
end
