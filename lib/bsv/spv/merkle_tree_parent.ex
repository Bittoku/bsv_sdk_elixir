defmodule BSV.SPV.MerkleTreeParent do
  @moduledoc """
  Merkle tree parent computation using double-SHA256.
  """

  alias BSV.Crypto

  @doc """
  Compute the Merkle tree parent of two children (internal byte order).

  Hashes are in little-endian (internal) byte order. They are concatenated
  directly, double-SHA256'd.
  """
  @spec compute(binary(), binary()) :: binary()
  def compute(<<left::binary-size(32)>>, <<right::binary-size(32)>>) do
    Crypto.sha256d(left <> right)
  end

  @doc """
  Compute the Merkle tree parent from display-order (big-endian) hex strings.

  Hex strings are byte-reversed, concatenated, double-SHA256'd, then reversed back.
  """
  @spec compute_hex(String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def compute_hex(left_hex, right_hex) do
    with {:ok, left} <- Base.decode16(left_hex, case: :mixed),
         {:ok, right} <- Base.decode16(right_hex, case: :mixed) do
      reversed_left = :binary.list_to_bin(:lists.reverse(:binary.bin_to_list(left)))
      reversed_right = :binary.list_to_bin(:lists.reverse(:binary.bin_to_list(right)))
      hash = Crypto.sha256d(reversed_left <> reversed_right)
      result = :binary.list_to_bin(:lists.reverse(:binary.bin_to_list(hash)))
      {:ok, Base.encode16(result, case: :lower)}
    else
      :error -> {:error, "invalid hex"}
    end
  end
end
