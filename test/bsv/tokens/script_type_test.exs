defmodule BSV.Tokens.ScriptTypeTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.ScriptType

  test "to_string for all types" do
    assert ScriptType.to_string(:p2pkh) == "P2PKH"
    assert ScriptType.to_string(:stas) == "STAS"
    assert ScriptType.to_string(:stas_btg) == "STAS-BTG"
    assert ScriptType.to_string(:dstas) == "dSTAS"
    assert ScriptType.to_string(:op_return) == "OP_RETURN"
    assert ScriptType.to_string(:unknown) == "Unknown"
  end
end
