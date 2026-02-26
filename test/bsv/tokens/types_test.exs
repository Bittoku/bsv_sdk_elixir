defmodule BSV.Tokens.TypesTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.{DstasSpendType, Payment, Destination, DstasDestination, DstasLockingParams, DstasOutputParams, TokenInput}

  describe "DstasSpendType" do
    test "to_byte for all types" do
      assert DstasSpendType.to_byte(:transfer) == 1
      assert DstasSpendType.to_byte(:freeze_unfreeze) == 2
      assert DstasSpendType.to_byte(:confiscation) == 3
      assert DstasSpendType.to_byte(:swap_cancellation) == 4
    end
  end

  describe "Payment struct" do
    test "creates with defaults" do
      p = %Payment{}
      assert p.txid == nil
      assert p.vout == nil
      assert p.satoshis == nil
    end
  end

  describe "Destination struct" do
    test "creates with values" do
      d = %Destination{address: "1abc", satoshis: 1000}
      assert d.address == "1abc"
      assert d.satoshis == 1000
    end
  end

  describe "DstasDestination struct" do
    test "creates with defaults" do
      d = %DstasDestination{address: "1abc", satoshis: 500, spend_type: :transfer}
      assert d.action_data == nil
    end
  end

  describe "DstasLockingParams struct" do
    test "creates with defaults" do
      p = %DstasLockingParams{address: "1abc", spend_type: :transfer}
      assert p.action_data == nil
    end
  end

  describe "DstasOutputParams struct" do
    test "creates with defaults" do
      p = %DstasOutputParams{satoshis: 100, owner_pkh: <<0::160>>, redemption_pkh: <<0::160>>}
      assert p.frozen == false
      assert p.freezable == true
      assert p.service_fields == []
      assert p.optional_data == []
    end
  end

  describe "TokenInput struct" do
    test "creates with values" do
      t = %TokenInput{txid: <<0::256>>, vout: 0, satoshis: 100}
      assert t.txid == <<0::256>>
    end
  end

  describe "ActionData type" do
    test "swap action data" do
      data = {:swap, <<0::256>>}
      assert elem(data, 0) == :swap
    end

    test "custom action data" do
      data = {:custom, "hello"}
      assert elem(data, 0) == :custom
    end
  end
end
