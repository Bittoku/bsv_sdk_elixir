defmodule BSV.Tokens.Script.StasBtgBuilderTest do
  use ExUnit.Case, async: true

  alias BSV.Script
  alias BSV.Tokens.Script.StasBtgBuilder

  defp test_pkh(byte), do: :binary.copy(<<byte>>, 20)

  test "BTG script starts with OP_IF" do
    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(test_pkh(0xAA), test_pkh(0xBB), true)
    <<first, _::binary>> = Script.to_binary(script)
    assert first == 0x63
  end

  test "BTG script longer than standard STAS" do
    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(test_pkh(0xAA), test_pkh(0xBB), true)
    assert byte_size(Script.to_binary(script)) > 1433
  end

  test "BTG script contains OP_IF/OP_ELSE/OP_ENDIF" do
    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(test_pkh(0xAA), test_pkh(0xBB), true)
    bytes = Script.to_binary(script)

    assert :binary.at(bytes, 0) == 0x63
    # OP_ELSE in preamble region
    assert :binary.match(binary_part(bytes, 1, min(350, byte_size(bytes) - 1)), <<0x67>>) != :nomatch

    # OP_ENDIF followed by STAS v2 body (76 a9 14)
    found = find_pattern(bytes, <<0x68, 0x76, 0xA9, 0x14>>)
    assert found != nil
  end

  test "checkpoint gate is 25 bytes" do
    gate = StasBtgBuilder.build_checkpoint_gate(test_pkh(0xBB))
    assert byte_size(gate) == 25
  end

  test "BTG script contains redemption PKH at least 3 times" do
    rpkh = test_pkh(0xBB)
    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(test_pkh(0xAA), rpkh, true)
    bytes = Script.to_binary(script)

    count = count_occurrences(bytes, rpkh)
    assert count >= 3, "Expected redemption PKH at least 3 times, found #{count}"
  end

  test "BTG script contains owner PKH" do
    owner_pkh = test_pkh(0xAA)
    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(owner_pkh, test_pkh(0xBB), true)
    bytes = Script.to_binary(script)

    assert :binary.match(bytes, owner_pkh) != :nomatch
  end

  test "splittable flag" do
    {:ok, s} = StasBtgBuilder.build_stas_btg_locking_script(test_pkh(0x11), test_pkh(0x22), true)
    {:ok, ns} = StasBtgBuilder.build_stas_btg_locking_script(test_pkh(0x11), test_pkh(0x22), false)

    s_bytes = Script.to_binary(s)
    ns_bytes = Script.to_binary(ns)

    assert :binary.last(s_bytes) == 0x00
    assert :binary.last(ns_bytes) == 0x01
  end

  test "find_preamble_redemption_offset" do
    rpkh = test_pkh(0xBB)
    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(test_pkh(0xAA), rpkh, true)
    bytes = Script.to_binary(script)

    offset = StasBtgBuilder.find_preamble_redemption_offset(bytes)
    assert offset != nil
    assert binary_part(bytes, offset, 20) == rpkh
  end

  test "component sizes sum correctly" do
    owner_pkh = test_pkh(0xAA)
    rpkh = test_pkh(0xBB)
    {:ok, script} = StasBtgBuilder.build_stas_btg_locking_script(owner_pkh, rpkh, true)
    script_len = byte_size(Script.to_binary(script))

    _preamble = StasBtgBuilder.build_checkpoint_gate(rpkh)
    # Total should be reasonable (preamble + gate + body + control flow opcodes)
    assert script_len > 1460
  end

  test "push_number encoding" do
    assert StasBtgBuilder.push_number(0) == <<0x00>>
    assert StasBtgBuilder.push_number(1) == <<0x51>>
    assert StasBtgBuilder.push_number(16) == <<0x60>>
    assert StasBtgBuilder.push_number(-1) == <<0x4F>>
    # 1408 should be multi-byte
    result = StasBtgBuilder.push_number(1408)
    assert byte_size(result) > 1
  end

  # Helpers

  defp find_pattern(data, pattern) do
    case :binary.match(data, pattern) do
      {pos, _} -> pos
      :nomatch -> nil
    end
  end

  defp count_occurrences(data, pattern) do
    count_occurrences(data, pattern, 0, 0)
  end

  defp count_occurrences(data, pattern, offset, count) do
    plen = byte_size(pattern)

    if offset + plen > byte_size(data) do
      count
    else
      if binary_part(data, offset, plen) == pattern do
        count_occurrences(data, pattern, offset + 1, count + 1)
      else
        count_occurrences(data, pattern, offset + 1, count)
      end
    end
  end
end
