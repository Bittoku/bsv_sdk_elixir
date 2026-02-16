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

    test "OP_NOT of 0 is truthy" do
      assert :ok = verify_asm("", "OP_0 OP_NOT")
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

    test "OP_NUMEQUAL" do
      assert :ok = verify_asm("", "OP_5 OP_5 OP_NUMEQUAL")
    end

    test "OP_LESSTHAN" do
      assert :ok = verify_asm("", "OP_3 OP_5 OP_LESSTHAN")
    end

    test "OP_GREATERTHAN" do
      assert :ok = verify_asm("", "OP_5 OP_3 OP_GREATERTHAN")
    end

    test "OP_BOOLAND" do
      assert :ok = verify_asm("", "OP_1 OP_1 OP_BOOLAND")
    end

    test "OP_BOOLOR" do
      assert :ok = verify_asm("", "OP_0 OP_1 OP_BOOLOR")
    end
  end

  describe "stack ops" do
    test "OP_DUP" do
      assert :ok = verify_asm("", "OP_5 OP_DUP OP_EQUAL")
    end

    test "OP_DROP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_DROP")
    end

    test "OP_SWAP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_SWAP OP_1 OP_EQUALVERIFY OP_2 OP_EQUAL")
    end

    test "OP_OVER" do
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_OVER OP_1 OP_EQUALVERIFY OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL"
               )
    end

    test "OP_ROT" do
      # [1 2 3] ROT -> [2 3 1]
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_3 OP_ROT OP_1 OP_EQUALVERIFY OP_3 OP_EQUALVERIFY OP_2 OP_EQUAL"
               )
    end

    test "OP_TUCK" do
      # [1 2] TUCK -> [2 1 2]
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_TUCK OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_2 OP_EQUAL"
               )
    end

    test "OP_2DUP" do
      assert :ok =
               verify_asm(
                 "",
                 "OP_1 OP_2 OP_2DUP OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL"
               )
    end

    test "OP_DEPTH" do
      assert :ok = verify_asm("OP_1 OP_2 OP_3", "OP_DEPTH OP_3 OP_EQUALVERIFY OP_1")
    end

    test "OP_PICK" do
      # [1 2 3] pick(2) -> [1 2 3 1]
      assert :ok = verify_asm("", "OP_1 OP_2 OP_3 OP_2 OP_PICK OP_1 OP_EQUALVERIFY OP_1")
    end

    test "OP_TOALTSTACK and OP_FROMALTSTACK" do
      assert :ok = verify_asm("OP_5", "OP_TOALTSTACK OP_FROMALTSTACK OP_5 OP_EQUAL")
    end

    test "OP_IFDUP with truthy" do
      assert :ok = verify_asm("", "OP_1 OP_IFDUP OP_EQUAL")
    end

    test "OP_SIZE" do
      {:ok, unlock} = Script.from_hex("03aabbcc")
      {:ok, lock} = Script.from_asm("OP_SIZE OP_3 OP_EQUALVERIFY OP_1")
      assert :ok = Interpreter.verify(unlock, lock)
    end

    test "OP_NIP" do
      assert :ok = verify_asm("", "OP_1 OP_2 OP_NIP OP_2 OP_EQUAL")
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

    test "nested IF" do
      assert :ok = verify_asm("", "OP_1 OP_IF OP_1 OP_IF OP_2 OP_ENDIF OP_ENDIF")
    end

    test "unbalanced IF errors" do
      assert {:error, _} = verify_asm("", "OP_1 OP_IF OP_1")
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
  end

  describe "splice ops" do
    test "OP_CAT" do
      {:ok, unlock} = Script.from_hex("01aa01bb")
      {:ok, lock} = Script.from_hex("7e02aabb87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end

    test "OP_SPLIT" do
      # Push 2-byte value, split at 1
      {:ok, unlock} = Script.from_hex("02aabb" <> "51")
      {:ok, lock} = Script.from_hex("7f" <> "01bb" <> "88" <> "01aa" <> "87")
      assert :ok = Interpreter.verify(unlock, lock, flags: [:utxo_after_genesis])
    end
  end

  describe "CHECKSIG" do
    test "returns error without sighash_fn" do
      assert {:error, :no_sighash_fn} = verify_asm("OP_1 OP_1", "OP_CHECKSIG")
    end

    test "works with sighash_fn" do
      # Provide a sighash_fn that always validates
      sighash_fn = fn _sig, _pubkey, _type -> {:ok, true} end
      assert :ok = verify_asm("OP_1 OP_1", "OP_CHECKSIG", sighash_fn: sighash_fn)
    end
  end

  describe "comparison" do
    test "OP_EQUAL" do
      assert :ok = verify_asm("", "OP_5 OP_5 OP_EQUAL")
    end

    test "OP_EQUALVERIFY success" do
      assert :ok = verify_asm("", "OP_5 OP_5 OP_EQUALVERIFY OP_1")
    end

    test "OP_EQUALVERIFY failure" do
      assert {:error, :equalverify_failed} = verify_asm("", "OP_5 OP_6 OP_EQUALVERIFY OP_1")
    end
  end
end
