defmodule BSV.Script.OpcodesTest do
  use ExUnit.Case, async: true

  alias BSV.Script.Opcodes

  describe "opcode_to_name/1" do
    test "returns correct names for common opcodes" do
      assert Opcodes.opcode_to_name(0x76) == "OP_DUP"
      assert Opcodes.opcode_to_name(0xA9) == "OP_HASH160"
      assert Opcodes.opcode_to_name(0x88) == "OP_EQUALVERIFY"
      assert Opcodes.opcode_to_name(0xAC) == "OP_CHECKSIG"
      assert Opcodes.opcode_to_name(0x00) == "OP_0"
      assert Opcodes.opcode_to_name(0x51) == "OP_1"
      assert Opcodes.opcode_to_name(0x6A) == "OP_RETURN"
    end

    test "returns OP_DATA_N for push opcodes" do
      assert Opcodes.opcode_to_name(0x01) == "OP_DATA_1"
      assert Opcodes.opcode_to_name(0x14) == "OP_DATA_20"
      assert Opcodes.opcode_to_name(0x4B) == "OP_DATA_75"
    end

    test "returns names for NOP opcodes" do
      assert Opcodes.opcode_to_name(0xB0) == "OP_NOP1"
      assert Opcodes.opcode_to_name(0xB9) == "OP_NOP10"
    end
  end

  describe "name_to_opcode/1" do
    test "returns correct byte for common names" do
      assert Opcodes.name_to_opcode("OP_DUP") == {:ok, 0x76}
      assert Opcodes.name_to_opcode("OP_HASH160") == {:ok, 0xA9}
      assert Opcodes.name_to_opcode("OP_CHECKSIG") == {:ok, 0xAC}
    end

    test "supports aliases" do
      assert Opcodes.name_to_opcode("OP_FALSE") == {:ok, 0x00}
      assert Opcodes.name_to_opcode("OP_TRUE") == {:ok, 0x51}
      assert Opcodes.name_to_opcode("OP_0") == {:ok, 0x00}
      assert Opcodes.name_to_opcode("OP_ONE") == {:ok, 0x51}
    end

    test "returns :error for unknown names" do
      assert Opcodes.name_to_opcode("OP_BOGUS") == :error
    end
  end
end
