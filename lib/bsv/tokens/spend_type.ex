defmodule BSV.Tokens.SpendType do
  @moduledoc """
  STAS protocol spending-type parameter.

  Every STAS unlocking script includes a spending-type value that tells the
  locking script which operation is being performed. This is a protocol-level
  concept shared across all STAS templates (standard, BTG, dSTAS).

  ## Values

  | Value | Atom                | Operation                              |
  |-------|---------------------|----------------------------------------|
  | 1     | `:transfer`         | Regular spending (transfer/split/merge/redeem) |
  | 2     | `:freeze_unfreeze`  | Freeze or unfreeze a token UTXO        |
  | 3     | `:confiscation`     | Forcible reassignment of ownership     |
  | 4     | `:swap_cancellation`| Cancel a standing swap offer           |
  """

  @type t :: :transfer | :freeze_unfreeze | :confiscation | :swap_cancellation

  @doc "Convert a spend type atom to its wire-format byte value."
  @spec to_byte(t()) :: byte()
  def to_byte(:transfer), do: 1
  def to_byte(:freeze_unfreeze), do: 2
  def to_byte(:confiscation), do: 3
  def to_byte(:swap_cancellation), do: 4

  @doc "Convert a wire-format byte value to a spend type atom."
  @spec from_byte(byte()) :: {:ok, t()} | {:error, :unknown_spend_type}
  def from_byte(1), do: {:ok, :transfer}
  def from_byte(2), do: {:ok, :freeze_unfreeze}
  def from_byte(3), do: {:ok, :confiscation}
  def from_byte(4), do: {:ok, :swap_cancellation}
  def from_byte(_), do: {:error, :unknown_spend_type}
end
