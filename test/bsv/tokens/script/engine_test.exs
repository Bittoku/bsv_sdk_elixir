defmodule BSV.Tokens.Script.EngineTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.ScriptFlags
  alias BSV.Tokens.Script.Engine

  defp contains?(haystack, needle), do: :binary.match(haystack, needle) != :nomatch

  test "embedded bodies have expected sizes, offsets, and OP_RETURN terminator" do
    assert Engine.byte_len(:v0_0_9) == 2899
    assert Engine.byte_len(:v0_0_11) == 3146
    # 0.0.11 = 0.0.9 + 247 bytes (NFT + augmentability, spec §15.6)
    assert Engine.byte_len(:v0_0_11) - Engine.byte_len(:v0_0_9) == 247
    # Redemption-offset pushes: 540b (2900) for 0.0.9, 4b0c (3147) for 0.0.11.
    assert contains?(Engine.template_bytes(:v0_0_9), <<0x02, 0x54, 0x0B>>)
    assert contains?(Engine.template_bytes(:v0_0_11), <<0x02, 0x4B, 0x0C>>)
    # Both bodies end in OP_RETURN.
    assert :binary.last(Engine.template_bytes(:v0_0_9)) == 0x6A
    assert :binary.last(Engine.template_bytes(:v0_0_11)) == 0x6A
  end

  test "select_engine follows the last flags byte (spec §15.5)" do
    assert Engine.select_engine(<<>>) == :v0_0_9
    assert Engine.select_engine(<<0x00>>) == :v0_0_9
    assert Engine.select_engine(<<0x01>>) == :v0_0_9
    assert Engine.select_engine(<<0x03>>) == :v0_0_9
    assert Engine.select_engine(<<0x04>>) == :v0_0_11
    assert Engine.select_engine(<<0x08>>) == :v0_0_11
    assert Engine.select_engine(<<0x0C>>) == :v0_0_11
    assert Engine.select_engine(<<0xAA, 0x0C>>) == :v0_0_11
    assert Engine.select_engine(<<0x0C, 0x00>>) == :v0_0_9
  end

  test "detect matches each known engine exactly, ignoring trailing bytes" do
    for rev <- Engine.all() do
      region = Engine.template_bytes(rev) <> :binary.copy(<<0x14>>, 21)
      assert Engine.detect(region) == {:ok, {rev, Engine.byte_len(rev)}}
    end
  end

  test "detect rejects an unknown or truncated engine" do
    assert Engine.detect(<<0x6D, 0x82, 0x73, 0x63>>) == :error
    assert Engine.detect(:binary.copy(<<0x00>>, 3200)) == :error
    short = :binary.part(Engine.template_bytes(:v0_0_9), 0, 2800)
    assert Engine.detect(short) == :error
  end

  test "ScriptFlags.engine/1 selects 0.0.11 for capability bits" do
    assert ScriptFlags.engine(%ScriptFlags{}) == :v0_0_9
    assert ScriptFlags.engine(%ScriptFlags{freezable: true}) == :v0_0_9
    assert ScriptFlags.engine(%ScriptFlags{nft: true}) == :v0_0_11
    assert ScriptFlags.engine(%ScriptFlags{nft: true, augmentable: true}) == :v0_0_11
  end

  test "build_stas3_locking_script_with_engine(:v0_0_9) matches the default builder" do
    alias BSV.Tokens.Script.Stas3Builder
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    {:ok, default} =
      Stas3Builder.build_stas3_locking_script(owner, redemption, nil, false, false, [], [])

    {:ok, pinned} =
      Stas3Builder.build_stas3_locking_script_with_engine(
        owner,
        redemption,
        nil,
        false,
        false,
        :v0_0_9,
        [],
        []
      )

    assert default == pinned

    # A 0.0.11 build is longer by the 247-byte engine delta.
    {:ok, v11} =
      Stas3Builder.build_stas3_locking_script_with_engine(
        owner,
        redemption,
        nil,
        false,
        %ScriptFlags{nft: true},
        :v0_0_11,
        [],
        []
      )

    assert byte_size(BSV.Script.to_binary(v11)) - byte_size(BSV.Script.to_binary(default)) == 247
  end
end
