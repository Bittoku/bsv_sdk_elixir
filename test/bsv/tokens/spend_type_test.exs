defmodule BSV.Tokens.SpendTypeTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.SpendType

  describe "to_byte/1" do
    test "encodes transfer" do
      assert SpendType.to_byte(:transfer) == 1
    end

    test "encodes freeze_unfreeze" do
      assert SpendType.to_byte(:freeze_unfreeze) == 2
    end

    test "encodes confiscation" do
      assert SpendType.to_byte(:confiscation) == 3
    end

    test "encodes swap_cancellation" do
      assert SpendType.to_byte(:swap_cancellation) == 4
    end
  end

  describe "from_byte/1" do
    test "decodes 1 to transfer" do
      assert SpendType.from_byte(1) == {:ok, :transfer}
    end

    test "decodes 2 to freeze_unfreeze" do
      assert SpendType.from_byte(2) == {:ok, :freeze_unfreeze}
    end

    test "decodes 3 to confiscation" do
      assert SpendType.from_byte(3) == {:ok, :confiscation}
    end

    test "decodes 4 to swap_cancellation" do
      assert SpendType.from_byte(4) == {:ok, :swap_cancellation}
    end

    test "rejects unknown byte" do
      assert SpendType.from_byte(0) == {:error, :unknown_spend_type}
      assert SpendType.from_byte(5) == {:error, :unknown_spend_type}
      assert SpendType.from_byte(255) == {:error, :unknown_spend_type}
    end
  end

  describe "backward compatibility with DstasSpendType" do
    alias BSV.Tokens.DstasSpendType

    test "DstasSpendType delegates to SpendType" do
      assert DstasSpendType.to_byte(:transfer) == SpendType.to_byte(:transfer)
      assert DstasSpendType.to_byte(:freeze_unfreeze) == SpendType.to_byte(:freeze_unfreeze)
      assert DstasSpendType.to_byte(:confiscation) == SpendType.to_byte(:confiscation)
      assert DstasSpendType.to_byte(:swap_cancellation) == SpendType.to_byte(:swap_cancellation)
    end
  end
end
