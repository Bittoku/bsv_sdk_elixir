defmodule BSV.Tokens.Script.Stas3BuilderTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.{Stas3Builder, Reader}

  test "build and read roundtrip unfrozen" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} = Stas3Builder.build_stas3_locking_script(owner, redemption, nil, false, true, [], [])
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas3
    assert parsed.stas3.owner == owner
    assert parsed.stas3.redemption == redemption
    assert parsed.stas3.frozen == false
  end

  test "build and read roundtrip frozen" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)

    {:ok, script} = Stas3Builder.build_stas3_locking_script(owner, redemption, nil, true, true, [], [])
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas3
    assert parsed.stas3.frozen == true
  end

  test "build flags freezable" do
    assert Stas3Builder.build_stas3_flags(true) == <<0x01>>
  end

  test "build flags not freezable" do
    assert Stas3Builder.build_stas3_flags(false) == <<0x00>>
  end

  test "build with service fields" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)
    service = [<<0x01, 0x02, 0x03>>]

    {:ok, script} = Stas3Builder.build_stas3_locking_script(owner, redemption, nil, false, false, service, [])
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas3
    assert parsed.stas3.owner == owner
    assert parsed.stas3.redemption == redemption
    assert length(parsed.stas3.service_fields) > 0
    assert hd(parsed.stas3.service_fields) == <<0x01, 0x02, 0x03>>
  end

  test "push_data empty" do
    assert Stas3Builder.push_data(<<>>) == <<0x00>>
  end

  test "push_data small" do
    assert Stas3Builder.push_data(<<0x42>>) == <<0x01, 0x42>>
  end

  test "push_data 75 bytes" do
    data = :binary.copy(<<0xFF>>, 75)
    result = Stas3Builder.push_data(data)
    assert <<75, ^data::binary-size(75)>> = result
  end

  test "push_data 76 bytes uses OP_PUSHDATA1" do
    data = :binary.copy(<<0xFF>>, 76)
    result = Stas3Builder.push_data(data)
    assert <<0x4C, 76, ^data::binary-size(76)>> = result
  end
end
