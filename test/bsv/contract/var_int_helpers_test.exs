defmodule BSV.Contract.VarIntHelpersTest do
  use ExUnit.Case, async: true

  alias BSV.Contract

  describe "VarIntHelpers script generation" do
    test "get_varint produces non-empty script" do
      ctx = %Contract{mfa: {__MODULE__, :test_get_varint, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 0
    end

    test "read_varint produces non-empty script" do
      ctx = %Contract{mfa: {__MODULE__, :test_read_varint, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 0
    end

    test "trim_varint produces non-empty script" do
      ctx = %Contract{mfa: {__MODULE__, :test_trim_varint, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 0
    end

    test "get_varint starts with OP_DUP (preserves original)" do
      ctx = %Contract{mfa: {__MODULE__, :test_get_varint, [%{}]}}
      script = Contract.to_script(ctx)
      assert hd(script.chunks) == {:op, 0x76}
    end
  end

  import BSV.Contract.VarIntHelpers

  def test_get_varint(ctx, _params), do: get_varint(ctx)
  def test_read_varint(ctx, _params), do: read_varint(ctx)
  def test_trim_varint(ctx, _params), do: trim_varint(ctx)
end
