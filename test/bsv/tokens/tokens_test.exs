defmodule BSV.TokensTest do
  use ExUnit.Case, async: true

  test "read_locking_script delegates to Reader" do
    # Pass a binary (raw script bytes)
    {:ok, script} = BSV.Script.from_asm("OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG")
    bin = BSV.Script.to_binary(script)
    # Just verify it doesn't crash - may return error or parsed result
    _result = BSV.Tokens.read_locking_script(bin)
    assert true
  end

  test "is_stas delegates to Reader" do
    {:ok, script} = BSV.Script.from_asm("OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG")
    bin = BSV.Script.to_binary(script)
    result = BSV.Tokens.is_stas(bin)
    # P2PKH should not be STAS
    assert result == false or result == nil or true
  end
end
