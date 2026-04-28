defmodule BSV.Tokens.TxType do
  @moduledoc """
  STAS 3.0 v0.1 §8.1 transaction-type (txType) parameter.

  Every STAS 3.0 unlocking script carries a 1-byte `txType` value (slot 18 in
  the spec §7 witness layout) describing the high-level shape of the spend:

  | Value | Atom            | Operation                                            |
  |-------|-----------------|------------------------------------------------------|
  | 0     | `:regular`      | Regular spend / split / 1-in/1-out                   |
  | 1     | `:atomic_swap`  | Atomic swap (counterparty trailing parameters apply) |
  | 2     | `:merge_2`      | Merge with 2 pieces                                  |
  | 3     | `:merge_3`      | Merge with 3 pieces                                  |
  | 4     | `:merge_4`      | Merge with 4 pieces                                  |
  | 5     | `:merge_5`      | Merge with 5 pieces                                  |
  | 6     | `:merge_6`      | Merge with 6 pieces                                  |
  | 7     | `:merge_7`      | Merge with 7 pieces                                  |

  Mirrors `BSV.Tokens.SpendType` in shape: `to_byte/1` and `from_byte/1`.
  """

  @type t ::
          :regular
          | :atomic_swap
          | :merge_2
          | :merge_3
          | :merge_4
          | :merge_5
          | :merge_6
          | :merge_7

  @doc "Convert a txType atom to its wire-format byte value (0..7)."
  @spec to_byte(t()) :: byte()
  def to_byte(:regular), do: 0
  def to_byte(:atomic_swap), do: 1
  def to_byte(:merge_2), do: 2
  def to_byte(:merge_3), do: 3
  def to_byte(:merge_4), do: 4
  def to_byte(:merge_5), do: 5
  def to_byte(:merge_6), do: 6
  def to_byte(:merge_7), do: 7

  @doc "Convert a wire-format byte value (0..7) to a txType atom."
  @spec from_byte(byte()) :: {:ok, t()} | {:error, :unknown_tx_type}
  def from_byte(0), do: {:ok, :regular}
  def from_byte(1), do: {:ok, :atomic_swap}
  def from_byte(2), do: {:ok, :merge_2}
  def from_byte(3), do: {:ok, :merge_3}
  def from_byte(4), do: {:ok, :merge_4}
  def from_byte(5), do: {:ok, :merge_5}
  def from_byte(6), do: {:ok, :merge_6}
  def from_byte(7), do: {:ok, :merge_7}
  def from_byte(_), do: {:error, :unknown_tx_type}
end
