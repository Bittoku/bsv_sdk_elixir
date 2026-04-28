defmodule BSV.Tokens.TxTypeTest do
  @moduledoc "STAS 3.0 v0.1 §8.1 txType enum coverage."
  use ExUnit.Case, async: true

  alias BSV.Tokens.TxType

  describe "to_byte/1" do
    test "encodes regular as 0" do
      assert TxType.to_byte(:regular) == 0
    end

    test "encodes atomic_swap as 1" do
      assert TxType.to_byte(:atomic_swap) == 1
    end

    test "encodes merge_2..merge_7 as 2..7" do
      for {atom, byte} <- [
            {:merge_2, 2},
            {:merge_3, 3},
            {:merge_4, 4},
            {:merge_5, 5},
            {:merge_6, 6},
            {:merge_7, 7}
          ] do
        assert TxType.to_byte(atom) == byte
      end
    end
  end

  describe "from_byte/1" do
    test "decodes 0 as regular" do
      assert TxType.from_byte(0) == {:ok, :regular}
    end

    test "decodes 1 as atomic_swap" do
      assert TxType.from_byte(1) == {:ok, :atomic_swap}
    end

    test "decodes 2..7 as merge variants" do
      for {byte, atom} <- [
            {2, :merge_2},
            {3, :merge_3},
            {4, :merge_4},
            {5, :merge_5},
            {6, :merge_6},
            {7, :merge_7}
          ] do
        assert TxType.from_byte(byte) == {:ok, atom}
      end
    end

    test "rejects out-of-range bytes" do
      assert TxType.from_byte(8) == {:error, :unknown_tx_type}
      assert TxType.from_byte(255) == {:error, :unknown_tx_type}
    end
  end

  test "round-trip every value 0..7" do
    for byte <- 0..7 do
      {:ok, atom} = TxType.from_byte(byte)
      assert TxType.to_byte(atom) == byte
    end
  end
end
