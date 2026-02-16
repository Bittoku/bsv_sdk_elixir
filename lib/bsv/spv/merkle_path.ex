defmodule BSV.SPV.MerklePath do
  @moduledoc """
  Merkle path (BUMP) types and verification — BRC-74 binary format.

  A MerklePath associates a transaction with a block via a sequence of
  hashes at each tree level.
  """

  import Bitwise

  alias BSV.VarInt
  alias BSV.SPV.MerkleTreeParent

  defmodule PathElement do
    @moduledoc "A single element in a Merkle path level."
    defstruct [:offset, :hash, :txid, :duplicate]

    @type t :: %__MODULE__{
            offset: non_neg_integer(),
            hash: binary() | nil,
            txid: boolean() | nil,
            duplicate: boolean() | nil
          }
  end

  @enforce_keys [:block_height, :path]
  defstruct [:block_height, :path]

  @type t :: %__MODULE__{
          block_height: non_neg_integer(),
          path: [[PathElement.t()]]
        }

  @doc "Parse a MerklePath from a hex string."
  @spec from_hex(String.t()) :: {:ok, t()} | {:error, String.t()}
  def from_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> from_bytes(bin)
      :error -> {:error, "invalid hex"}
    end
  end

  @doc "Parse a MerklePath from binary data (BRC-74)."
  @spec from_bytes(binary()) :: {:ok, t()} | {:error, String.t()}
  def from_bytes(data) when byte_size(data) < 37 do
    {:error, "BUMP bytes do not contain enough data to be valid"}
  end

  def from_bytes(data) do
    {:ok, {block_height, rest}} = VarInt.decode(data)
    <<tree_height::8, rest2::binary>> = rest

    case read_levels(rest2, tree_height, []) do
      {:ok, path, _rest} ->
        {:ok, %__MODULE__{block_height: block_height, path: path}}

      {:error, _} = err ->
        err
    end
  end

  @doc "Serialize to BRC-74 binary format."
  @spec to_bytes(t()) :: binary()
  def to_bytes(%__MODULE__{} = mp) do
    header = VarInt.encode(mp.block_height) <> <<length(mp.path)::8>>

    levels_bin =
      Enum.reduce(mp.path, <<>>, fn level, acc ->
        level_bin =
          Enum.reduce(level, <<>>, fn elem, lacc ->
            flags = (if elem.duplicate == true, do: 1, else: 0) ||| (if elem.txid == true, do: 2, else: 0)
            hash_bin = if (flags &&& 1) == 0 and elem.hash != nil, do: elem.hash, else: <<>>
            lacc <> VarInt.encode(elem.offset) <> <<flags::8>> <> hash_bin
          end)

        acc <> VarInt.encode(length(level)) <> level_bin
      end)

    header <> levels_bin
  end

  @doc "Serialize to hex string."
  @spec to_hex(t()) :: String.t()
  def to_hex(%__MODULE__{} = mp), do: Base.encode16(to_bytes(mp), case: :lower)

  @doc """
  Compute the Merkle root given a transaction hash (32 bytes, internal byte order).

  If `txid` is nil, uses the first available hash from level 0.
  """
  @spec compute_root(t(), binary() | nil) :: {:ok, binary()} | {:error, String.t()}
  def compute_root(%__MODULE__{path: path} = mp, txid \\ nil) do
    txid = txid || find_first_hash(hd(path))

    if txid == nil do
      {:error, "no hash found at level 0"}
    else
      # Single tx in block
      if length(path) == 1 and length(hd(path)) == 1 do
        {:ok, txid}
      else
        indexed = build_index(mp)
        compute_root_walk(path, indexed, txid)
      end
    end
  end

  @doc "Compute root from hex txid string (display order, byte-reversed)."
  @spec compute_root_hex(t(), String.t() | nil) :: {:ok, String.t()} | {:error, String.t()}
  def compute_root_hex(%__MODULE__{} = mp, txid_hex \\ nil) do
    txid = if txid_hex, do: hex_to_internal(txid_hex), else: nil

    case compute_root(mp, txid) do
      {:ok, root} -> {:ok, internal_to_hex(root)}
      error -> error
    end
  end

  # --- Private ---

  defp read_levels(rest, 0, acc), do: {:ok, Enum.reverse(acc), rest}

  defp read_levels(data, n, acc) do
    {:ok, {n_leaves, rest}} = VarInt.decode(data)

    case read_leaves(rest, n_leaves, []) do
      {:ok, level, rest2} ->
        sorted = Enum.sort_by(level, & &1.offset)
        read_levels(rest2, n - 1, [sorted | acc])

      error ->
        error
    end
  end

  defp read_leaves(rest, 0, acc), do: {:ok, Enum.reverse(acc), rest}

  defp read_leaves(data, n, acc) do
    {:ok, {offset, rest}} = VarInt.decode(data)
    <<flags::8, rest2::binary>> = rest

    dup = (flags &&& 1) != 0
    is_txid = (flags &&& 2) != 0

    {hash, rest3} =
      if dup do
        {nil, rest2}
      else
        <<h::binary-size(32), r::binary>> = rest2
        {h, r}
      end

    elem = %PathElement{
      offset: offset,
      hash: hash,
      txid: if(is_txid, do: true, else: nil),
      duplicate: if(dup, do: true, else: nil)
    }

    read_leaves(rest3, n - 1, [elem | acc])
  end

  defp find_first_hash([]), do: nil
  defp find_first_hash([%{hash: h} | _]) when h != nil, do: h
  defp find_first_hash([_ | rest]), do: find_first_hash(rest)

  defp build_index(%__MODULE__{path: path}) do
    Enum.map(path, fn level ->
      Map.new(level, fn elem -> {elem.offset, elem} end)
    end)
  end

  defp get_offset_leaf(indexed, layer, offset) do
    case Map.get(Enum.at(indexed, layer), offset) do
      nil when layer == 0 ->
        nil

      nil ->
        # Try computing from children
        prev_offset = offset * 2
        left = get_offset_leaf(indexed, layer - 1, prev_offset)
        right = get_offset_leaf(indexed, layer - 1, prev_offset + 1)

        with %{hash: lh} when lh != nil <- left,
             %{} = r <- right do
          parent_hash =
            if r.duplicate == true do
              MerkleTreeParent.compute(lh, lh)
            else
              if r.hash != nil, do: MerkleTreeParent.compute(lh, r.hash), else: nil
            end

          if parent_hash do
            %PathElement{offset: offset, hash: parent_hash}
          else
            nil
          end
        else
          _ -> nil
        end

      elem ->
        elem
    end
  end

  defp compute_root_walk(path, indexed, txid) do
    # Find the leaf matching this txid
    tx_leaf =
      Enum.find(hd(path), fn l -> l.hash == txid end)

    if tx_leaf == nil do
      {:error, "the BUMP does not contain the txid"}
    else
      index = tx_leaf.offset
      num_levels = length(path)

      result =
        Enum.reduce_while(0..(num_levels - 1), {:ok, txid}, fn height, {:ok, working} ->
          offset = bxor(index >>> height, 1)

          case get_offset_leaf(indexed, height, offset) do
            nil ->
              {:halt, {:error, "we do not have a hash for this index at height: #{height}"}}

            leaf ->
              new_hash =
                if leaf.duplicate == true do
                  MerkleTreeParent.compute(working, working)
                else
                  if leaf.hash == nil do
                    {:halt, {:error, "missing hash at height #{height} offset #{offset}"}}
                  else
                    if rem(offset, 2) != 0 do
                      MerkleTreeParent.compute(working, leaf.hash)
                    else
                      MerkleTreeParent.compute(leaf.hash, working)
                    end
                  end
                end

              case new_hash do
                {:halt, _} = err -> err
                hash -> {:cont, {:ok, hash}}
              end
          end
        end)

      result
    end
  end

  defp hex_to_internal(hex) do
    {:ok, bytes} = Base.decode16(hex, case: :mixed)
    :binary.list_to_bin(:lists.reverse(:binary.bin_to_list(bytes)))
  end

  defp internal_to_hex(bytes) do
    :binary.list_to_bin(:lists.reverse(:binary.bin_to_list(bytes)))
    |> Base.encode16(case: :lower)
  end
end
