defmodule BSV.Tokens.ScriptFlagsTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.ScriptFlags

  describe "encode/1" do
    test "no flags" do
      assert ScriptFlags.encode(%ScriptFlags{}) == <<0x00>>
    end

    test "freezable only" do
      assert ScriptFlags.encode(%ScriptFlags{freezable: true}) == <<0x01>>
    end

    test "confiscatable only" do
      assert ScriptFlags.encode(%ScriptFlags{confiscatable: true}) == <<0x02>>
    end

    test "both flags" do
      assert ScriptFlags.encode(%ScriptFlags{freezable: true, confiscatable: true}) == <<0x03>>
    end
  end

  describe "decode/1" do
    test "decodes 0x00 to no flags" do
      assert ScriptFlags.decode(<<0x00>>) == {:ok, %ScriptFlags{freezable: false, confiscatable: false}}
    end

    test "decodes 0x01 to freezable" do
      assert ScriptFlags.decode(<<0x01>>) == {:ok, %ScriptFlags{freezable: true, confiscatable: false}}
    end

    test "decodes 0x02 to confiscatable" do
      assert ScriptFlags.decode(<<0x02>>) == {:ok, %ScriptFlags{freezable: false, confiscatable: true}}
    end

    test "decodes 0x03 to both" do
      assert ScriptFlags.decode(<<0x03>>) == {:ok, %ScriptFlags{freezable: true, confiscatable: true}}
    end

    test "decodes empty binary to defaults" do
      assert ScriptFlags.decode(<<>>) == {:ok, %ScriptFlags{}}
    end

    test "ignores trailing bytes" do
      assert ScriptFlags.decode(<<0x01, 0xFF>>) == {:ok, %ScriptFlags{freezable: true, confiscatable: false}}
    end
  end

  describe "service_field_count/1" do
    test "no flags → 0" do
      assert ScriptFlags.service_field_count(%ScriptFlags{}) == 0
    end

    test "freezable only → 1" do
      assert ScriptFlags.service_field_count(%ScriptFlags{freezable: true}) == 1
    end

    test "confiscatable only → 1" do
      assert ScriptFlags.service_field_count(%ScriptFlags{confiscatable: true}) == 1
    end

    test "both → 2" do
      assert ScriptFlags.service_field_count(%ScriptFlags{freezable: true, confiscatable: true}) == 2
    end
  end

  describe "roundtrip" do
    test "encode → decode is identity" do
      for f <- [false, true], c <- [false, true] do
        flags = %ScriptFlags{freezable: f, confiscatable: c}
        assert {:ok, ^flags} = flags |> ScriptFlags.encode() |> ScriptFlags.decode()
      end
    end
  end
end
