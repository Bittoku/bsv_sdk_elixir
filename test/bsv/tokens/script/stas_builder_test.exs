defmodule BSV.Tokens.Script.StasBuilderTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.{StasBuilder, Reader}

  test "build and read roundtrip splittable" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, true)
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas
    assert parsed.stas.owner_hash == owner
    assert parsed.stas.redemption_hash == redemption
    assert parsed.stas.flags == <<0x00>>
  end

  test "build and read roundtrip non-splittable" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, false)
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas
    assert parsed.stas.flags == <<0x01>>
  end

  test "build preserves token_id" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, true)
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.stas.token_id.pkh == redemption
  end

  test "template is 1431 bytes base" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, true)
    # Template (1431) + flags (2 bytes: OP_DATA_1 + flag)
    assert byte_size(BSV.Script.to_binary(script)) == 1433
  end
end
