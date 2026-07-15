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

    test "nft only" do
      assert ScriptFlags.encode(%ScriptFlags{nft: true}) == <<0x04>>
    end

    test "augmentable bit" do
      assert ScriptFlags.encode(%ScriptFlags{nft: true, augmentable: true}) == <<0x0C>>
    end

    test "all four bits" do
      flags = %ScriptFlags{freezable: true, confiscatable: true, nft: true, augmentable: true}
      assert ScriptFlags.encode(flags) == <<0x0F>>
    end
  end

  describe "decode/1" do
    test "decodes every byte 0x00..0x0F back to its bits" do
      for byte <- 0..15 do
        {:ok, flags} = ScriptFlags.decode(<<byte>>)
        assert ScriptFlags.to_byte(flags) == byte
      end
    end

    test "decodes 0x04 to nft" do
      assert ScriptFlags.decode(<<0x04>>) ==
               {:ok, %ScriptFlags{nft: true}}
    end

    test "decodes empty binary to defaults" do
      assert ScriptFlags.decode(<<>>) == {:ok, %ScriptFlags{}}
    end

    test "reads the LAST byte of a multi-byte field (spec §15.5)" do
      # aa0c → capabilities active (nft + augmentable)
      assert ScriptFlags.decode(<<0xAA, 0x0C>>) ==
               {:ok, %ScriptFlags{nft: true, augmentable: true}}

      # 0c00 → none
      assert ScriptFlags.decode(<<0x0C, 0x00>>) == {:ok, %ScriptFlags{}}
    end
  end

  describe "validate/1" do
    test "rejects a standalone AUGMENTABLE bit (§15.2)" do
      assert ScriptFlags.validate(%ScriptFlags{augmentable: true}) ==
               {:error, :augmentable_requires_nft}
    end

    test "accepts AUGMENTABLE alongside NFT" do
      assert ScriptFlags.validate(%ScriptFlags{nft: true, augmentable: true}) == :ok
    end

    test "accepts plain and freeze/confiscate combinations" do
      assert ScriptFlags.validate(%ScriptFlags{}) == :ok
      assert ScriptFlags.validate(%ScriptFlags{freezable: true, confiscatable: true}) == :ok
      assert ScriptFlags.validate(%ScriptFlags{nft: true}) == :ok
    end
  end

  describe "service_field_count/1" do
    test "counts only freezable + confiscatable; NFT/AUGMENTABLE add none" do
      assert ScriptFlags.service_field_count(%ScriptFlags{}) == 0
      assert ScriptFlags.service_field_count(%ScriptFlags{freezable: true}) == 1
      assert ScriptFlags.service_field_count(%ScriptFlags{confiscatable: true}) == 1

      assert ScriptFlags.service_field_count(%ScriptFlags{freezable: true, confiscatable: true}) ==
               2

      assert ScriptFlags.service_field_count(%ScriptFlags{nft: true, augmentable: true}) == 0
    end
  end

  describe "roundtrip" do
    test "encode → decode is identity across all four bits" do
      for fz <- [false, true], c <- [false, true], n <- [false, true], a <- [false, true] do
        flags = %ScriptFlags{freezable: fz, confiscatable: c, nft: n, augmentable: a}
        assert {:ok, ^flags} = flags |> ScriptFlags.encode() |> ScriptFlags.decode()
      end
    end
  end
end
