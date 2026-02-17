defmodule BSV.Tokens.Script.DstasBuilderTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.{DstasBuilder, Reader}

  test "build and read roundtrip unfrozen" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} = DstasBuilder.build_dstas_locking_script(owner, redemption, nil, false, true, [], [])
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :dstas
    assert parsed.dstas.owner == owner
    assert parsed.dstas.redemption == redemption
    assert parsed.dstas.frozen == false
  end

  test "build and read roundtrip frozen" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)

    {:ok, script} = DstasBuilder.build_dstas_locking_script(owner, redemption, nil, true, true, [], [])
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :dstas
    assert parsed.dstas.frozen == true
  end

  test "build flags freezable" do
    assert DstasBuilder.build_dstas_flags(true) == <<0x01>>
  end

  test "build flags not freezable" do
    assert DstasBuilder.build_dstas_flags(false) == <<0x00>>
  end

  test "build with service fields" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)
    service = [<<0x01, 0x02, 0x03>>]

    {:ok, script} = DstasBuilder.build_dstas_locking_script(owner, redemption, nil, false, false, service, [])
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :dstas
    assert parsed.dstas.owner == owner
    assert parsed.dstas.redemption == redemption
    assert length(parsed.dstas.service_fields) > 0
    assert hd(parsed.dstas.service_fields) == <<0x01, 0x02, 0x03>>
  end

  test "push_data empty" do
    assert DstasBuilder.push_data(<<>>) == <<0x00>>
  end

  test "push_data small" do
    assert DstasBuilder.push_data(<<0x42>>) == <<0x01, 0x42>>
  end

  test "push_data 75 bytes" do
    data = :binary.copy(<<0xFF>>, 75)
    result = DstasBuilder.push_data(data)
    assert <<75, ^data::binary-size(75)>> = result
  end

  test "push_data 76 bytes uses OP_PUSHDATA1" do
    data = :binary.copy(<<0xFF>>, 76)
    result = DstasBuilder.push_data(data)
    assert <<0x4C, 76, ^data::binary-size(76)>> = result
  end
end
