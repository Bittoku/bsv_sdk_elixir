defmodule BSV.Tokens.Script.TemplatesTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Templates

  test "stas_v2_prefix" do
    assert Templates.stas_v2_prefix() == <<0x76, 0xA9, 0x14>>
  end

  test "stas_v2_marker" do
    assert Templates.stas_v2_marker() == <<0x88, 0xAC, 0x69, 0x76, 0xAA, 0x60>>
  end

  test "stas_v2 constants" do
    assert Templates.stas_v2_owner_offset() == 3
    assert Templates.pkh_len() == 20
    assert Templates.stas_v2_marker_offset() == 23
    assert Templates.stas_v2_template_len() == 1431
    assert Templates.stas_v2_op_return_offset() == 1409
    assert Templates.stas_v2_redemption_offset() == 1411
    assert Templates.stas_v2_min_len() == 1432
  end

  test "dstas constants" do
    assert Templates.dstas_base_prefix() == <<0x6D, 0x82, 0x73, 0x63>>
    assert Templates.dstas_base_template_len() == 2812
  end

  test "p2pkh constants" do
    assert Templates.p2pkh_len() == 25
    assert Templates.p2pkh_prefix() == <<0x76, 0xA9, 0x14>>
    assert Templates.p2pkh_suffix() == <<0x88, 0xAC>>
  end
end
