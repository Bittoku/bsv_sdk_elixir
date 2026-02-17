defmodule BSV.Transaction.OutputTest do
  use ExUnit.Case, async: true

  alias BSV.Transaction.Output

  test "new/0 creates default output" do
    out = Output.new()
    assert out.satoshis == 0
    assert out.change == false
  end

  test "to_binary/from_binary roundtrip" do
    {:ok, script} = BSV.Script.from_asm("OP_1")
    out = %Output{satoshis: 50000, locking_script: script}
    bin = Output.to_binary(out)
    assert {:ok, decoded, <<>>} = Output.from_binary(bin)
    assert decoded.satoshis == 50000
  end

  test "from_binary with insufficient data" do
    assert {:error, :insufficient_data} = Output.from_binary(<<1, 2, 3>>)
  end

  test "from_binary with invalid output" do
    # Valid satoshis but truncated script
    assert {:error, :invalid_output} = Output.from_binary(<<0::little-64, 0xFF>>)
  end

  test "locking_script_hex" do
    {:ok, script} = BSV.Script.from_asm("OP_1")
    out = %Output{satoshis: 0, locking_script: script}
    hex = Output.locking_script_hex(out)
    assert is_binary(hex)
    assert String.length(hex) > 0
  end
end
