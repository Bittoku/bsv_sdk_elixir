defmodule BSV.Tokens.Script.ReaderTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Reader
  alias BSV.Tokens.Script.StasBuilder
  alias BSV.Tokens.Script.DstasBuilder

  defp build_stas_script(owner, redemption, splittable) do
    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, splittable)
    BSV.Script.to_binary(script)
  end

  test "classify STAS v2" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)
    script_bin = build_stas_script(owner, redemption, true)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :stas
    assert parsed.stas.owner_hash == owner
    assert parsed.stas.redemption_hash == redemption
  end

  test "classify P2PKH" do
    {:ok, script_bin} = Base.decode16("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac", case: :mixed)
    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :p2pkh
    assert parsed.stas == nil
  end

  test "classify OP_RETURN" do
    {:ok, script_bin} = Base.decode16("6a0568656c6c6f", case: :mixed)
    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :op_return
  end

  test "classify OP_FALSE OP_RETURN" do
    {:ok, script_bin} = Base.decode16("006a0568656c6c6f", case: :mixed)
    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :op_return
  end

  test "classify unknown" do
    parsed = Reader.read_locking_script(<<0xFF, 0xFE, 0xFD>>)
    assert parsed.script_type == :unknown
  end

  test "classify empty" do
    parsed = Reader.read_locking_script(<<>>)
    assert parsed.script_type == :unknown
  end

  test "is_stas true" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)
    script_bin = build_stas_script(owner, redemption, true)
    assert Reader.is_stas(script_bin) == true
  end

  test "is_stas false for P2PKH" do
    {:ok, script_bin} = Base.decode16("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac", case: :mixed)
    assert Reader.is_stas(script_bin) == false
  end

  test "is_stas false for empty" do
    assert Reader.is_stas(<<>>) == false
  end

  test "STAS v2 extracts token_id" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)
    script_bin = build_stas_script(owner, redemption, true)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.stas.token_id.pkh == redemption
  end

  test "STAS v2 extracts flags splittable" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)
    script_bin = build_stas_script(owner, redemption, true)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.stas.flags == <<0x00>>
  end

  test "STAS v2 extracts flags non-splittable" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)
    script_bin = build_stas_script(owner, redemption, false)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.stas.flags == <<0x01>>
  end

  test "garbage bytes no panic" do
    for len <- 0..50 do
      script = :binary.list_to_bin(for i <- 0..(len - 1)//1, do: rem(i * 7 + 3, 256))
      Reader.read_locking_script(script)
      Reader.is_stas(script)
    end
  end

  test "classify DSTAS unfrozen" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)
    {:ok, script} = DstasBuilder.build_dstas_locking_script(owner, redemption, nil, false, true, [], [])
    script_bin = BSV.Script.to_binary(script)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :dstas
    assert parsed.dstas.owner == owner
    assert parsed.dstas.redemption == redemption
    assert parsed.dstas.frozen == false
  end

  test "classify DSTAS frozen" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)
    {:ok, script} = DstasBuilder.build_dstas_locking_script(owner, redemption, nil, true, true, [], [])
    script_bin = BSV.Script.to_binary(script)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :dstas
    assert parsed.dstas.frozen == true
  end
end
