defmodule BSV.Contract.PushTxHelpersTest do
  use ExUnit.Case, async: true

  alias BSV.Contract

  describe "preimage field extraction scripts" do
    test "get_version produces script starting with OP_DUP" do
      ctx = %Contract{mfa: {__MODULE__, :test_get_version, [%{}]}}
      script = Contract.to_script(ctx)
      assert hd(script.chunks) == {:op, 0x76}  # OP_DUP
    end

    test "get_prevouts_hash produces script" do
      ctx = %Contract{mfa: {__MODULE__, :test_get_prevouts_hash, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 0
    end

    test "get_satoshis produces script" do
      ctx = %Contract{mfa: {__MODULE__, :test_get_satoshis, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 0
    end

    test "get_outputs_hash produces script" do
      ctx = %Contract{mfa: {__MODULE__, :test_get_outputs_hash, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 0
    end

    test "get_lock_time produces script" do
      ctx = %Contract{mfa: {__MODULE__, :test_get_lock_time, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 0
    end
  end

  describe "push_tx" do
    test "without context pushes 181 zero bytes" do
      ctx = %Contract{mfa: {__MODULE__, :test_push_tx, [%{}]}}
      script = Contract.to_script(ctx)
      [{:data, data}] = script.chunks
      assert byte_size(data) == 181
      assert data == <<0::1448>>
    end
  end

  describe "check_tx" do
    test "produces non-trivial script" do
      ctx = %Contract{mfa: {__MODULE__, :test_check_tx, [%{}]}}
      script = Contract.to_script(ctx)
      # check_tx compiles to ~438 bytes of opcodes
      assert length(script.chunks) > 30
      # Last opcode should be OP_CHECKSIG
      assert List.last(script.chunks) == {:op, 0xAC}
    end

    test "check_tx! ends with OP_CHECKSIGVERIFY" do
      ctx = %Contract{mfa: {__MODULE__, :test_check_tx_verify, [%{}]}}
      script = Contract.to_script(ctx)
      assert List.last(script.chunks) == {:op, 0xAD}
    end
  end

  describe "check_tx_opt" do
    test "produces compact script" do
      ctx = %Contract{mfa: {__MODULE__, :test_check_tx_opt, [%{}]}}
      script = Contract.to_script(ctx)
      assert length(script.chunks) > 5
      assert List.last(script.chunks) == {:op, 0xAC}
    end

    test "check_tx_opt! ends with OP_CHECKSIGVERIFY" do
      ctx = %Contract{mfa: {__MODULE__, :test_check_tx_opt_verify, [%{}]}}
      script = Contract.to_script(ctx)
      assert List.last(script.chunks) == {:op, 0xAD}
    end
  end

  import BSV.Contract.Helpers
  import BSV.Contract.PushTxHelpers

  def test_get_version(ctx, _), do: get_version(ctx)
  def test_get_prevouts_hash(ctx, _), do: get_prevouts_hash(ctx)
  def test_get_satoshis(ctx, _), do: get_satoshis(ctx)
  def test_get_outputs_hash(ctx, _), do: get_outputs_hash(ctx)
  def test_get_lock_time(ctx, _), do: get_lock_time(ctx)
  def test_push_tx(ctx, _), do: push_tx(ctx)
  def test_check_tx(ctx, _), do: check_tx(ctx)
  def test_check_tx_verify(ctx, _), do: check_tx!(ctx)
  def test_check_tx_opt(ctx, _), do: check_tx_opt(ctx)
  def test_check_tx_opt_verify(ctx, _), do: check_tx_opt!(ctx)
end
