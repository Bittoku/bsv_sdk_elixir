defmodule BSV.Tokens.ScriptType do
  @moduledoc "Classification of script types relevant to token operations."

  @type t :: :p2pkh | :stas | :stas_btg | :dstas | :op_return | :unknown

  @spec to_string(t()) :: String.t()
  def to_string(:p2pkh), do: "P2PKH"
  def to_string(:stas), do: "STAS"
  def to_string(:stas_btg), do: "STAS-BTG"
  def to_string(:dstas), do: "dSTAS"
  def to_string(:op_return), do: "OP_RETURN"
  def to_string(:unknown), do: "Unknown"
end
