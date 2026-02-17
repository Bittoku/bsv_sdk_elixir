defmodule BSV.Script.ScriptNumTest do
  use ExUnit.Case, async: true

  alias BSV.Script.ScriptNum

  describe "decode_num/1" do
    test "empty binary is 0" do
      assert ScriptNum.decode_num(<<>>) == 0
    end

    test "single byte positive" do
      assert ScriptNum.decode_num(<<1>>) == 1
      assert ScriptNum.decode_num(<<127>>) == 127
    end

    test "single byte negative" do
      assert ScriptNum.decode_num(<<0x81>>) == -1
      assert ScriptNum.decode_num(<<0xFF>>) == -127
    end

    test "two byte positive" do
      assert ScriptNum.decode_num(<<0x00, 0x01>>) == 256
      assert ScriptNum.decode_num(<<0x80, 0x00>>) == 128
    end

    test "two byte negative" do
      assert ScriptNum.decode_num(<<0x80, 0x80>>) == -128
    end

    test "multi-byte values" do
      assert ScriptNum.decode_num(<<0x00, 0x00, 0x01>>) == 65536
    end
  end

  describe "encode_num/1" do
    test "zero encodes to empty" do
      assert ScriptNum.encode_num(0) == <<>>
    end

    test "positive values" do
      assert ScriptNum.encode_num(1) == <<1>>
      assert ScriptNum.encode_num(127) == <<127>>
      assert ScriptNum.encode_num(128) == <<0x80, 0x00>>
      assert ScriptNum.encode_num(255) == <<0xFF, 0x00>>
      assert ScriptNum.encode_num(256) == <<0x00, 0x01>>
    end

    test "negative values" do
      assert ScriptNum.encode_num(-1) == <<0x81>>
      assert ScriptNum.encode_num(-127) == <<0xFF>>
      assert ScriptNum.encode_num(-128) == <<0x80, 0x80>>
      assert ScriptNum.encode_num(-256) == <<0x00, 0x81>>
    end

    test "roundtrip" do
      for n <- [-1000, -1, 0, 1, 127, 128, 255, 256, 1000, 65535, -65535] do
        assert ScriptNum.decode_num(ScriptNum.encode_num(n)) == n
      end
    end
  end

  describe "minimally_encoded?/1" do
    test "empty is minimal" do
      assert ScriptNum.minimally_encoded?(<<>>)
    end

    test "single non-zero byte is minimal" do
      assert ScriptNum.minimally_encoded?(<<1>>)
      assert ScriptNum.minimally_encoded?(<<0x7F>>)
      assert ScriptNum.minimally_encoded?(<<0x81>>)
    end

    test "single zero byte is NOT minimal" do
      refute ScriptNum.minimally_encoded?(<<0>>)
    end

    test "leading zeros detection" do
      # 0x0100 - the last byte has 0x00 in upper bits, prev byte has 0x80 set -> minimal
      assert ScriptNum.minimally_encoded?(<<0x80, 0x00>>)
      # 0x0100 where last byte is 0 and prev doesn't have 0x80 -> not minimal
      refute ScriptNum.minimally_encoded?(<<0x00, 0x00>>)
    end
  end
end
