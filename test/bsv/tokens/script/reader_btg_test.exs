defmodule BSV.Tokens.Script.ReaderBtgTest do
  use ExUnit.Case, async: true

  alias BSV.Script
  alias BSV.Tokens.Script.{Reader, StasBtgBuilder}

  test "reader classifies STAS-BTG script correctly" do
    owner_pkh = :binary.copy(<<0xAA>>, 20)
    rpkh = :binary.copy(<<0xBB>>, 20)

    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(owner_pkh, rpkh, true)
    bytes = Script.to_binary(script)
    parsed = Reader.read_locking_script(bytes)

    assert parsed.script_type == :stas_btg
    assert parsed.stas != nil
    assert parsed.stas.owner_hash == owner_pkh
    assert parsed.stas.redemption_hash == rpkh
  end

  test "standard STAS v2 still classified as :stas" do
    owner_pkh = :binary.copy(<<0xAA>>, 20)
    rpkh = :binary.copy(<<0xBB>>, 20)

    {:ok, script} =
      BSV.Tokens.Script.StasBuilder.build_stas_locking_script(owner_pkh, rpkh, true)

    bytes = Script.to_binary(script)
    parsed = Reader.read_locking_script(bytes)

    assert parsed.script_type == :stas
  end

  test "STAS-BTG non-splittable flag" do
    {:ok, script} =
      StasBtgBuilder.build_stas_btg_locking_script(
        :binary.copy(<<0xAA>>, 20),
        :binary.copy(<<0xBB>>, 20),
        false
      )

    bytes = Script.to_binary(script)
    parsed = Reader.read_locking_script(bytes)

    assert parsed.script_type == :stas_btg
    assert parsed.stas.flags == <<0x01>>
  end
end
