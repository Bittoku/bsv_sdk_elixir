defmodule BSV.Script.ScriptTest do
  use ExUnit.Case, async: true

  alias BSV.Script

  describe "from_binary/1 and to_binary/1" do
    test "roundtrip for P2PKH script" do
      hex = "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac"
      bin = Base.decode16!(hex, case: :lower)
      {:ok, script} = Script.from_binary(bin)
      assert Script.to_binary(script) == bin
    end

    test "roundtrip for empty script" do
      {:ok, script} = Script.from_binary(<<>>)
      assert Script.to_binary(script) == <<>>
    end

    test "errors on truncated data push" do
      assert {:error, :data_too_small} = Script.from_binary(<<0x05, 0x00, 0x00>>)
    end
  end

  describe "from_hex/1 and to_hex/1" do
    test "roundtrip" do
      hex = "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac"
      {:ok, script} = Script.from_hex(hex)
      assert Script.to_hex(script) == hex
    end

    test "invalid hex" do
      assert {:error, :invalid_hex} = Script.from_hex("ZZZZ")
    end
  end

  describe "from_asm/1 and to_asm/1" do
    test "roundtrip for P2PKH" do
      asm =
        "OP_DUP OP_HASH160 e2a623699e81b291c0327f408fea765d534baa2a OP_EQUALVERIFY OP_CHECKSIG"

      {:ok, script} = Script.from_asm(asm)
      assert Script.to_asm(script) == asm
    end

    test "hex -> asm -> hex roundtrip" do
      hex = "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac"
      {:ok, script} = Script.from_hex(hex)
      asm = Script.to_asm(script)
      {:ok, script2} = Script.from_asm(asm)
      assert Script.to_hex(script2) == hex
    end

    test "empty asm" do
      {:ok, script} = Script.from_asm("")
      assert Script.to_asm(script) == ""
    end
  end

  describe "classification" do
    test "is_p2pkh?" do
      {:ok, script} = Script.from_hex("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
      assert Script.is_p2pkh?(script)
    end

    test "is_p2pkh? false for P2SH" do
      {:ok, script} = Script.from_hex("a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87")
      refute Script.is_p2pkh?(script)
    end

    test "is_p2sh?" do
      {:ok, script} = Script.from_hex("a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87")
      assert Script.is_p2sh?(script)
    end

    test "is_op_return? with OP_FALSE OP_RETURN" do
      {:ok, script} = Script.from_hex("006a0568656c6c6f")
      assert Script.is_op_return?(script)
    end

    test "is_op_return? false for P2PKH" do
      {:ok, script} = Script.from_hex("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
      refute Script.is_op_return?(script)
    end
  end

  describe "builders" do
    test "p2pkh_lock" do
      pkh = Base.decode16!("e2a623699e81b291c0327f408fea765d534baa2a", case: :lower)
      script = Script.p2pkh_lock(pkh)
      assert Script.to_hex(script) == "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac"
      assert Script.is_p2pkh?(script)
    end

    test "p2pkh_unlock" do
      sig = :crypto.strong_rand_bytes(72)
      pubkey = :crypto.strong_rand_bytes(33)
      script = Script.p2pkh_unlock(sig, pubkey)
      assert length(script.chunks) == 2
    end

    test "op_return" do
      script = Script.op_return([<<"hello">>, <<"world">>])
      assert Script.is_op_return?(script)
      hex = Script.to_hex(script)
      assert String.starts_with?(hex, "006a")
    end
  end

  describe "get_pubkey_hash/1" do
    test "extracts PKH from P2PKH" do
      {:ok, script} = Script.from_hex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
      assert {:ok, pkh} = Script.get_pubkey_hash(script)
      assert Base.encode16(pkh, case: :lower) == "e2a623699e81b291c0327f408fea765d534baa2a"
    end

    test "returns :error for non-P2PKH" do
      {:ok, script} = Script.from_hex("a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87")
      assert :error = Script.get_pubkey_hash(script)
    end
  end

  describe "PUSHDATA encodings" do
    test "PUSHDATA1 roundtrip" do
      data = :binary.copy(<<0xAA>>, 80)
      script = %Script{chunks: [{:data, data}]}
      bin = Script.to_binary(script)
      # Should use PUSHDATA1 (0x4C)
      assert <<0x4C, 80, _rest::binary>> = bin
      {:ok, script2} = Script.from_binary(bin)
      assert script2.chunks == script.chunks
    end

    test "PUSHDATA2 roundtrip" do
      data = :binary.copy(<<0xBB>>, 256)
      script = %Script{chunks: [{:data, data}]}
      bin = Script.to_binary(script)
      assert <<0x4D, _::binary>> = bin
      {:ok, script2} = Script.from_binary(bin)
      assert script2.chunks == script.chunks
    end
  end
end
