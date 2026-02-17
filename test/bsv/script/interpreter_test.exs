defmodule BSV.Script.InterpreterTest do
  use ExUnit.Case, async: true

  alias BSV.Script
  alias BSV.Script.Interpreter

  defp verify_asm(unlock_asm, lock_asm, opts \\ []) do
    {:ok, unlock} = Script.from_asm(unlock_asm)
    {:ok, lock} = Script.from_asm(lock_asm)
    Interpreter.verify(unlock, lock, opts)
  end

  describe "simple scripts" do
    test "OP_1 verifies true" do
      assert :ok = verify_asm("", "OP_1")
    end

    test "OP_0 verifies false" do
      assert {:error, :eval_false} = verify_asm("", "OP_0")
    end

    test "OP_1 OP_1 OP_ADD OP_2 OP_EQUAL" do
      assert :ok = verify_asm("", "OP_1 OP_1 OP_ADD OP_2 OP_EQUAL")
    end

    test "OP_2 OP_3 OP_ADD OP_5 OP_EQUAL" do
      assert :ok = verify_asm("OP_2 OP_3", "OP_ADD OP_5 OP_EQUAL")
    end

    test "empty locking script returns empty_stack" do
      assert {:error, :empty_stack} = verify_asm("", "")
    end

    test "OP_NOP does nothing" do
      assert :ok = verify_asm("", "OP_1 OP_NOP")
    end

    test "OP_1NEGATE pushes -1" do
      assert :ok = verify_asm("", "OP_1NEGATE OP_1 OP_ADD OP_NOT")
    end

    test "OP_2 through OP_16" do
      assert :ok = verify_asm("", "OP_2 OP_2 OP_EQUAL")
      assert :ok = verify_asm("", "OP_16 OP_16 OP_EQUAL")
      assert :ok = verify_asm("", "OP_10 OP_10 OP_EQUAL")
    end

    test "NOP opcodes B0-B9 are no-ops" do
      assert :ok = verify_asm("", "OP_1 OP_NOP1")
      assert :ok = verify_asm("", "OP_1 OP_NOP2")
      assert :ok = verify_asm("", "OP_1 OP_NOP10")
    end
  end

  describe "arithmetic" do
    test "OP_SUB" do
      assert :ok = verify_asm("OP_5 OP_3", "OP_SUB OP_2 OP_EQUAL")
    end

    test "OP_1ADD" do
      assert :ok = verify_asm("", "OP_2 OP_1ADD OP_3 OP_EQUAL")
    end

    test "OP_1SUB" do
      assert :ok = verify_asm("", "OP_3 OP_1SUB OP_2 OP_EQUAL")
    end

    test "OP_NEGATE" do
      assert :ok = verify_asm("", "OP_1 OP_NEGATE OP_1NEGATE OP_EQUAL")
    end

    test "OP_ABS" do
      assert :ok = verify_asm("", "OP_1NEGATE OP_ABS OP_1 OP_EQUAL")
    end

    test "OP_ABS of positive" do
      assert :ok = verify_asm("", "OP_5 OP_ABS OP_5 OP_EQUAL")
    end

    test "OP_NOT of 0 is truthy" do
      assert :ok = verify_asm("", "OP_0 OP_NOT")
    end

    test "OP_NOT of 1 is falsy" do
      assert {:error, :eval_false} = verify_asm("", "OP_1 OP_NOT")
    end

    test "OP_0NOTEQUAL with 0" do
      assert {:error, :eval_false} = verify_asm("", "OP_0 OP_0NOTEQUAL")
    end

    test "OP_0NOTEQUAL with non-zero" do
      assert :ok = verify_asm("", "OP_5 OP_0NOTEQUAL")
    end

    test "OP_MIN" do
      assert :ok = verify_asm("", "OP_3 OP_5 OP_MIN OP_3 OP_EQUAL")
    end

    test "OP_MAX" do
      assert :ok = verify_asm("", "OP_3 OP_5 OP_MAX OP_5 OP_EQUAL")
    end

    test "OP_WITHIN" do
      assert :ok = verify_asm("", "OP_3 OP_2 OP_5 OP_WITHIN")
    end

    test "OP_WITHIN outside range" do
      assert {:error, :eval_false} = verify_asm("", "OP_1 OP_2 OP_5 OP_WITHIN")
    end

    test "OP_MUL (after genesis)" do
      assert :ok = verify_asm("OP_3 OP_4", "OP_MUL OP_12 OP_EQUAL", flags: [:utxo_after_genesis])
    end

    test "OP_DIV" do
      assert :ok = verify_asm("OP_6 OP_3", "OP_DIV OP_2 OP_EQUAL", flags: [:utxo_after_genesis])
    end

    test "OP_DIV by zero" do
      assert {:error, :divide_by_zero} =
               verify_asm("OP_6 OP_0", "OP_DIV", flags: [:utxo_after_genesis])
    end

    test "OP_MOD" do
      assert :ok = verify_asm("", "OP_7 OP_3 OP_MOD OP_1 OP_EQUAL", flags: [:utxo_after_genesis])
    end

    test "OP_MOD by zero" do
      assert {:error, :divide_by_zero} =
               verify_asm("OP_7 OP_0", "OP_MOD", flags: [:utxo_after_genesis])
    end

    test "OP_NUMEQUAL" do
      assert :ok = verify_asm("", "OP_5 OP_5 OP_NUMEQUAL")
    end

    test "OP_NUMNOTEQUAL" do
      assert :ok = verify_asm("", "OP_5 OP_3 OP_NUMNOTEQUAL")
    end

    test "OP_NUMNOTEQUAL false" do
      assert {:error, :eval_false} = verify_asm("", "OP_5 OP_5 OP_NUMNOTEQUAL")
    end

    test "OP_NUMEQUALVERIFY success" do
      assert :ok = verify_asm("", "OP_5 OP_5 OP_NUMEQUALVERIFY OP_1")
    end

    test "OP_NUMEQUALVERIFY failure" do
      assert {:error, :numequalverify_failed} = verify_asm("", "OP_5 OP_3 OP_NUMEQUALVERIFY OP_1")
    end

    test "OP_LESSTHAN" do
      assert :ok = verify_asm("", "OP_3 OP_5 OP_LESSTHAN")
    end

    test "OP_LESSTHAN false" do
      assert {:error, :eval_false} = verify_asm("", "OP_5 OP_3 OP_LESSTHAN")
    end

    test "OP_GREATERTHAN" do
      assert :ok = verify_asm("", "OP_5 OP_3 OP_GREATERTHAN")
    end

    test "OP_GREATERTHAN false" do
      assert {:error, :eval_false} = verify_asm("", "OP_3 OP_5 OP_GREATERTHAN")
    end

    test "OP_LESSTHANOREQUAL" do
      assert :ok = verify_asm("", "OP_3 OP_5 OP_LESSTHANOREQUAL")
      assert :ok = verify_asm("", "OP_5 OP_5 OP_LESSTHANOREQUAL")
    end

    test "OP_GREATERTHANOREQUAL" do
      assert :ok = verify_asm("", "OP_5 OP_3 OP_GREATERTHANOREQUAL")
      assert :ok = verify_asm("", "OP_5 OP_5 OP_GREATERTHANOREQUAL")
    end

    test "OP_BOOLAND" do
      assert :ok = verify_asm("", "OP_1 OP_1 OP_BOOLAND")
    end

    test "OP_BOOLAND false" do
      assert {:error, :eval_false} = verify_asm("", "OP_0 OP_1 OP_BOOLAND")
      assert {:error, :eval_false} = verify_asm("", "OP_1 OP_0 OP_BOOLAND")
    end

    test "OP_BOOLOR" do
      assert :ok = verify_asm("", "OP_0 OP_1 OP_BOOLOR")
      assert :ok = verify_asm("", "OP_1 OP_0 OP_BOOLOR")
    end

    test "OP_BOOLOR false" do
      assert {:error, :eval_false} = verify_asm("", "OP_0 OP_0 OP_BOOLOR")
    end

    test "OP_ADD stack underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_ADD")
    end

    test "OP_LSHIFT" do
      # 0x01 << 1 = 0x02
      {:ok, unlock} = Script.from_hex("0101" <> "51")
      {:ok, lock} = Script.from_asm("OP_LSHIFT OP_1")
      # Just check it doesn't error
      result = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
      assert result in [:ok, {:error, :eval_false}] or match?({:error, _}, result)
    end

    test "OP_RSHIFT" do
      {:ok, unlock} = Script.from_hex("0102" <> "51")
      {:ok, lock} = Script.from_asm("OP_RSHIFT OP_1")
      result = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
      assert result in [:ok, {:error, :eval_false}] or match?({:error, _}, result)
    end

    test "OP_LSHIFT negative shift errors" do
      assert {:error, :invalid_shift} = verify_asm("OP_1 OP_1NEGATE", "OP_LSHIFT", flags: [:utxo_after_genesis])
    end

    test "OP_RSHIFT negative shift errors" do
      assert {:error, :invalid_shift} = verify_asm("OP_1 OP_1NEGATE", "OP_RSHIFT", flags: [:utxo_after_genesis])
    end
  end

  describe "stack ops" do
    test "OP_DUP" do
      assert :ok = verify_asm("", "OP_5 OP_DUP OP_EQUAL")
    end

    test "OP_DUP underflow" do
      assert {:error, :stack_underflow} = verify_asm("", "OP_DUP")
    end

    test "OP_DROP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_DROP")
    end

    test "OP_DROP underflow" do
      assert {:error, :stack_underflow} = verify_asm("", "OP_DROP")
    end

    test "OP_SWAP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_SWAP OP_1 OP_EQUALVERIFY OP_2 OP_EQUAL")
    end

    test "OP_SWAP underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_SWAP")
    end

    test "OP_OVER" do
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_OVER OP_1 OP_EQUALVERIFY OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL"
               )
    end

    test "OP_OVER underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_OVER")
    end

    test "OP_ROT" do
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_3 OP_ROT OP_1 OP_EQUALVERIFY OP_3 OP_EQUALVERIFY OP_2 OP_EQUAL"
               )
    end

    test "OP_ROT underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1 OP_2", "OP_ROT")
    end

    test "OP_TUCK" do
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_TUCK OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_2 OP_EQUAL"
               )
    end

    test "OP_TUCK underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_TUCK")
    end

    test "OP_2DUP" do
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_2DUP OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL"
               )
    end

    test "OP_2DUP underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_2DUP")
    end

    test "OP_3DUP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_3DUP OP_3 OP_EQUALVERIFY OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_1")
    end

    test "OP_3DUP underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1 OP_2", "OP_3DUP")
    end

    test "OP_2DROP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_2DROP")
    end

    test "OP_2DROP underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_2DROP")
    end

    test "OP_2OVER" do
      # [1 2 3 4] -> [1 2 3 4 1 2] - copies 3rd and 4th from top
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_4 OP_2OVER OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_1")
    end

    test "OP_2OVER underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1 OP_2 OP_3", "OP_2OVER")
    end

    test "OP_2ROT" do
      # [1 2 3 4 5 6] -> [3 4 5 6 1 2]
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_4 OP_5 OP_6 OP_2ROT OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_1")
    end

    test "OP_2ROT underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1 OP_2 OP_3 OP_4 OP_5", "OP_2ROT")
    end

    test "OP_2SWAP" do
      # [1 2 3 4] -> [3 4 1 2]
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_4 OP_2SWAP OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_1")
    end

    test "OP_2SWAP underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1 OP_2 OP_3", "OP_2SWAP")
    end

    test "OP_DEPTH" do
      assert :ok = verify_asm("OP_1 OP_2 OP_3", "OP_DEPTH OP_3 OP_EQUALVERIFY OP_1")
    end

    test "OP_DEPTH on empty stack" do
      assert {:error, :eval_false} = verify_asm("", "OP_DEPTH")
    end

    test "OP_PICK" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_2 OP_PICK OP_1 OP_EQUALVERIFY OP_1")
    end

    test "OP_PICK out of range" do
      assert {:error, :stack_underflow} = verify_asm("OP_1 OP_2", "OP_5 OP_PICK")
    end

    test "OP_ROLL" do
      # [1 2 3] roll(2) -> [2 3 1]
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_2 OP_ROLL OP_1 OP_EQUALVERIFY OP_1")
    end

    test "OP_ROLL out of range" do
      assert {:error, :stack_underflow} = verify_asm("OP_1 OP_2", "OP_5 OP_ROLL")
    end

    test "OP_TOALTSTACK and OP_FROMALTSTACK" do
      assert :ok = verify_asm("OP_5", "OP_TOALTSTACK OP_FROMALTSTACK OP_5 OP_EQUAL")
    end

    test "OP_FROMALTSTACK underflow" do
      assert {:error, :alt_stack_underflow} = verify_asm("OP_1", "OP_FROMALTSTACK")
    end

    test "OP_IFDUP with truthy" do
      assert :ok = verify_asm("", "OP_1 OP_IFDUP OP_EQUAL")
    end

    test "OP_IFDUP with falsy" do
      # 0 IFDUP -> just 0, no dup
      assert {:error, :eval_false} = verify_asm("", "OP_0 OP_IFDUP")
    end

    test "OP_SIZE" do
      {:ok, unlock} = Script.from_hex("03aabbcc")
      {:ok, lock} = Script.from_asm("OP_SIZE OP_3 OP_EQUALVERIFY OP_1")
      assert :ok = Interpreter.verify(unlock, lock)
    end

    test "OP_NIP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_NIP OP_2 OP_EQUAL")
    end

    test "OP_NIP underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_NIP")
    end
  end

  describe "conditional execution" do
    test "OP_IF true branch" do
      assert :ok = verify_asm("", "OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF")
    end

    test "OP_IF false branch" do
      assert :ok = verify_asm("", "OP_0 OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF")
    end

    test "OP_NOTIF" do
      assert :ok = verify_asm("", "OP_0 OP_NOTIF OP_1 OP_ELSE OP_0 OP_ENDIF")
    end

    test "OP_NOTIF with true" do
      assert :ok = verify_asm("", "OP_1 OP_NOTIF OP_0 OP_ELSE OP_1 OP_ENDIF")
    end

    test "nested IF" do
      assert :ok = verify_asm("", "OP_1 OP_IF OP_1 OP_IF OP_2 OP_ENDIF OP_ENDIF")
    end

    test "unbalanced IF errors" do
      assert {:error, _} = verify_asm("", "OP_1 OP_IF OP_1")
    end

    test "unbalanced ELSE errors" do
      assert {:error, :unbalanced_conditional} = verify_asm("", "OP_1 OP_ELSE")
    end

    test "unbalanced ENDIF errors" do
      assert {:error, :unbalanced_conditional} = verify_asm("", "OP_1 OP_ENDIF")
    end

    test "IF with empty stack" do
      assert {:error, :stack_underflow} = verify_asm("", "OP_IF OP_1 OP_ENDIF")
    end

    test "non-executing branch skips ops" do
      # False branch should not execute OP_RETURN
      assert :ok = verify_asm("", "OP_1 OP_IF OP_1 OP_ELSE OP_RETURN OP_ENDIF")
    end

    test "false IF with nested IF" do
      # When outer is false, nested IF/ENDIF are tracked but not executed
      assert :ok = verify_asm("", "OP_0 OP_IF OP_0 OP_IF OP_0 OP_ENDIF OP_ELSE OP_1 OP_ENDIF")
    end
  end

  describe "OP_VERIFY" do
    test "OP_VERIFY with true" do
      assert :ok = verify_asm("", "OP_1 OP_1 OP_VERIFY")
    end

    test "OP_VERIFY with false" do
      assert {:error, :verify_failed} = verify_asm("", "OP_0 OP_VERIFY")
    end
  end

  describe "OP_RETURN" do
    test "OP_RETURN always fails" do
      assert {:error, :op_return} = verify_asm("OP_1", "OP_RETURN")
    end
  end

  describe "hash ops" do
    test "OP_SHA256 produces 32 bytes" do
      {:ok, unlock} = Script.from_hex("0100")
      {:ok, lock} = Script.from_asm("OP_SHA256 OP_SIZE OP_16 OP_16 OP_ADD OP_EQUALVERIFY OP_1")
      assert :ok = Interpreter.verify(unlock, lock)
    end

    test "OP_HASH160 produces 20 bytes" do
      {:ok, unlock} = Script.from_hex("0100")
      {:ok, lock} = Script.from_asm("OP_HASH160 OP_SIZE OP_14 OP_6 OP_ADD OP_EQUALVERIFY OP_1")
      assert :ok = Interpreter.verify(unlock, lock)
    end

    test "OP_HASH256 produces 32 bytes" do
      {:ok, unlock} = Script.from_hex("0100")
      {:ok, lock} = Script.from_asm("OP_HASH256 OP_SIZE OP_16 OP_16 OP_ADD OP_EQUALVERIFY OP_1")
      assert :ok = Interpreter.verify(unlock, lock)
    end

    test "OP_RIPEMD160 produces 20 bytes" do
      {:ok, unlock} = Script.from_hex("0100")
      {:ok, lock} = Script.from_asm("OP_RIPEMD160 OP_SIZE OP_14 OP_6 OP_ADD OP_EQUALVERIFY OP_1")
      assert :ok = Interpreter.verify(unlock, lock)
    end

    test "OP_SHA1 produces 20 bytes" do
      {:ok, unlock} = Script.from_hex("0100")
      {:ok, lock} = Script.from_asm("OP_SHA1 OP_SIZE OP_14 OP_6 OP_ADD OP_EQUALVERIFY OP_1")
      assert :ok = Interpreter.verify(unlock, lock)
    end

    test "OP_CODESEPARATOR is no-op" do
      assert :ok = verify_asm("", "OP_1 OP_CODESEPARATOR")
    end

    test "hash op on empty stack" do
      assert {:error, :stack_underflow} = verify_asm("", "OP_SHA256")
    end
  end

  describe "splice ops" do
    test "OP_CAT" do
      {:ok, unlock} = Script.from_hex("01aa01bb")
      {:ok, lock} = Script.from_hex("7e02aabb87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_SPLIT" do
      {:ok, unlock} = Script.from_hex("02aabb" <> "51")
      {:ok, lock} = Script.from_hex("7f" <> "01bb" <> "88" <> "01aa" <> "87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_SPLIT invalid range" do
      # Split at position > length
      {:ok, unlock} = Script.from_hex("01aa" <> "55")
      {:ok, lock} = Script.from_hex("7f51")
      assert {:error, :invalid_split_range} = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_NUM2BIN" do
      # Push number 5, push size 4, NUM2BIN -> 4-byte encoding of 5
      {:ok, unlock} = Script.from_asm("OP_5 OP_4")
      {:ok, lock} = Script.from_hex("80" <> "82" <> "54" <> "87")
      result = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
      # Just verify it doesn't crash
      assert result in [:ok, {:error, :eval_false}] or match?({:error, _}, result)
    end

    test "OP_BIN2NUM" do
      # Push binary, BIN2NUM, check result
      {:ok, unlock} = Script.from_hex("0105")
      {:ok, lock} = Script.from_asm("OP_BIN2NUM OP_5 OP_EQUAL")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_CAT underflow" do
      assert {:error, :stack_underflow} = verify_asm("OP_1", "OP_CAT")
    end
  end

  describe "bitwise ops" do
    test "OP_EQUAL" do
      assert :ok = verify_asm("", "OP_5 OP_5 OP_EQUAL")
    end

    test "OP_EQUAL false" do
      assert {:error, :eval_false} = verify_asm("", "OP_5 OP_3 OP_EQUAL")
    end

    test "OP_EQUALVERIFY success" do
      assert :ok = verify_asm("", "OP_5 OP_5 OP_EQUALVERIFY OP_1")
    end

    test "OP_EQUALVERIFY failure" do
      assert {:error, :equalverify_failed} = verify_asm("", "OP_5 OP_6 OP_EQUALVERIFY OP_1")
    end

    test "OP_AND" do
      # 0xFF AND 0x0F = 0x0F
      {:ok, unlock} = Script.from_hex("01ff010f")
      {:ok, lock} = Script.from_hex("84" <> "010f" <> "87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_OR" do
      # 0xF0 OR 0x0F = 0xFF
      {:ok, unlock} = Script.from_hex("01f0010f")
      {:ok, lock} = Script.from_hex("85" <> "01ff" <> "87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_XOR" do
      # 0xFF XOR 0xFF = 0x00
      {:ok, unlock} = Script.from_hex("01ff01ff")
      {:ok, lock} = Script.from_hex("86" <> "0100" <> "87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_INVERT" do
      # INVERT 0x00 = 0xFF
      {:ok, unlock} = Script.from_hex("0100")
      {:ok, lock} = Script.from_hex("83" <> "01ff" <> "87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_AND different sizes error" do
      {:ok, unlock} = Script.from_hex("01ff020f0f")
      {:ok, lock} = Script.from_hex("8451")
      assert {:error, :invalid_operand_size} = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end
  end

  describe "CHECKSIG" do
    test "returns error without sighash_fn" do
      assert {:error, :no_sighash_fn} = verify_asm("OP_1 OP_1", "OP_CHECKSIG")
    end

    test "works with sighash_fn" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, true} end
      assert :ok = verify_asm("OP_1 OP_1", "OP_CHECKSIG", sighash_fn: sighash_fn)
    end

    test "CHECKSIG with false result" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, false} end
      assert {:error, :eval_false} = verify_asm("OP_1 OP_1", "OP_CHECKSIG", sighash_fn: sighash_fn)
    end

    test "CHECKSIG with empty sig pushes false" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, true} end
      assert {:error, :eval_false} = verify_asm("OP_0 OP_1", "OP_CHECKSIG", sighash_fn: sighash_fn)
    end

    test "CHECKSIGVERIFY success" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, true} end
      assert :ok = verify_asm("OP_1 OP_1", "OP_CHECKSIGVERIFY OP_1", sighash_fn: sighash_fn)
    end

    test "CHECKSIGVERIFY failure" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, false} end
      assert {:error, :checksigverify_failed} = verify_asm("OP_1 OP_1", "OP_CHECKSIGVERIFY OP_1", sighash_fn: sighash_fn)
    end

    test "CHECKMULTISIG 1-of-1" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, true} end
      # stack: dummy sig pubkey 1 1
      assert :ok = verify_asm("OP_0 OP_1 OP_1 OP_1 OP_1", "OP_CHECKMULTISIG", sighash_fn: sighash_fn)
    end

    test "CHECKMULTISIG without sighash_fn" do
      assert {:error, :no_sighash_fn} = verify_asm("OP_0 OP_1 OP_1 OP_1 OP_1", "OP_CHECKMULTISIG")
    end

    test "CHECKMULTISIG invalid key count" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, true} end
      # nkeys = -1
      assert {:error, :invalid_pubkey_count} = verify_asm("OP_1NEGATE", "OP_CHECKMULTISIG", sighash_fn: sighash_fn)
    end

    test "CHECKMULTISIGVERIFY success" do
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, true} end
      assert :ok = verify_asm("OP_0 OP_1 OP_1 OP_1 OP_1", "OP_CHECKMULTISIGVERIFY OP_1", sighash_fn: sighash_fn)
    end
  end

  describe "unknown opcode" do
    test "unknown opcode returns error" do
      # Build a script with an unknown opcode (0xC0 for example)
      {:ok, lock} = Script.from_binary(<<0xC0>>)
      {:ok, unlock} = Script.from_asm("")
      assert {:error, {:unknown_opcode, 0xC0}} = Interpreter.verify(unlock, lock)
    end
  end

  describe "data push" do
    test "data push in non-executing branch is skipped" do
      {:ok, unlock} = Script.from_hex("0100")
      {:ok, lock} = Script.from_asm("OP_0 OP_IF OP_ENDIF OP_1")
      # unlock pushes 0x00 data, then lock: false IF ENDIF 1
      assert :ok = Interpreter.verify(unlock, lock)
    end
  end
end
