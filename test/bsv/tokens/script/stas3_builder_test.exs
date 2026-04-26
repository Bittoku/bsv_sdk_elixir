defmodule BSV.Tokens.Script.Stas3BuilderTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.{Stas3Builder, Reader}

  test "build and read roundtrip unfrozen" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner, redemption, nil, false, true, [], [])

    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas3
    assert parsed.stas3.owner == owner
    assert parsed.stas3.redemption == redemption
    assert parsed.stas3.frozen == false
  end

  test "build and read roundtrip frozen" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner, redemption, nil, true, true, [], [])

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

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner, redemption, nil, false, false, service, [])

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

  # ── STAS 3.0 v0.1 §6.2 freeze marker conversion (Item J) ────────────────────

  describe "freeze_var2 / unfreeze_var2 round trip" do
    # Each row is {label, original_var2_wire_bytes}.
    # `freeze_var2(orig)` then `unfreeze_var2(...)` must reproduce `orig`.
    table = [
      {"OP_0 (empty push)", <<0x00>>},
      {"OP_1", <<0x51>>},
      {"OP_2", <<0x52>>},
      {"OP_3", <<0x53>>},
      {"OP_4", <<0x54>>},
      {"OP_5", <<0x55>>},
      {"OP_6", <<0x56>>},
      {"OP_7", <<0x57>>},
      {"OP_8", <<0x58>>},
      {"OP_9", <<0x59>>},
      {"OP_10", <<0x5A>>},
      {"OP_11", <<0x5B>>},
      {"OP_12", <<0x5C>>},
      {"OP_13", <<0x5D>>},
      {"OP_14", <<0x5E>>},
      {"OP_15", <<0x5F>>},
      {"OP_16", <<0x60>>},
      {"OP_1NEGATE", <<0x4F>>},
      {"direct push 1B", <<0x01, 0xAB>>},
      {"direct push 32B", <<32>> <> :binary.copy(<<0x77>>, 32)},
      {"direct push 75B", <<75>> <> :binary.copy(<<0x77>>, 75)},
      {"OP_PUSHDATA1 76B", <<0x4C, 76>> <> :binary.copy(<<0x88>>, 76)},
      {"OP_PUSHDATA2 300B", <<0x4D, 0x2C, 0x01>> <> :binary.copy(<<0x99>>, 300)}
    ]

    for {label, orig} <- table do
      test "round-trip: #{label}" do
        orig = unquote(orig)
        frozen = Stas3Builder.freeze_var2(orig)
        unfrozen = Stas3Builder.unfreeze_var2(frozen)
        assert unfrozen == orig
      end
    end
  end

  test "freeze_var2 maps OP_0 → OP_2 directly" do
    assert Stas3Builder.freeze_var2(<<0x00>>) == <<0x52>>
    assert Stas3Builder.unfreeze_var2(<<0x52>>) == <<0x00>>
  end

  test "freeze_var2 prepends 0x02 to pushdata payload (direct push case)" do
    # Original: 1-byte direct push of 0xAB
    assert Stas3Builder.freeze_var2(<<0x01, 0xAB>>) == <<0x02, 0x02, 0xAB>>
    # Original: 5-byte direct push
    payload = <<0xDE, 0xAD, 0xBE, 0xEF, 0x42>>
    expected = <<6>> <> <<0x02>> <> payload
    assert Stas3Builder.freeze_var2(<<5>> <> payload) == expected
  end

  test "freeze_var2 converts bare opcodes OP_1..OP_16 to pushdata then prepends 0x02" do
    # OP_1 pushes 0x01 → frozen form = push of <<0x02, 0x01>>
    assert Stas3Builder.freeze_var2(<<0x51>>) == <<0x02, 0x02, 0x01>>
    # OP_5 pushes 0x05 → frozen form = push of <<0x02, 0x05>>
    assert Stas3Builder.freeze_var2(<<0x55>>) == <<0x02, 0x02, 0x05>>
    # OP_16 pushes 0x10
    assert Stas3Builder.freeze_var2(<<0x60>>) == <<0x02, 0x02, 0x10>>
    # OP_1NEGATE pushes 0x81
    assert Stas3Builder.freeze_var2(<<0x4F>>) == <<0x02, 0x02, 0x81>>
  end

  # ── STAS 3.0 v0.1 §7 unlocking-script amount encoding (Item K) ──────────────

  describe "encode_unlock_amount minimal-LE" do
    test "0 → empty push" do
      assert Stas3Builder.encode_unlock_amount(0) == <<0x00>>
    end

    test "1 → 1 byte" do
      assert Stas3Builder.encode_unlock_amount(1) == <<0x01, 0x01>>
    end

    test "0xFF → 1 byte" do
      assert Stas3Builder.encode_unlock_amount(0xFF) == <<0x01, 0xFF>>
    end

    test "0x100 → 2 bytes" do
      assert Stas3Builder.encode_unlock_amount(0x100) == <<0x02, 0x00, 0x01>>
    end

    test "0xFFFF → 2 bytes" do
      assert Stas3Builder.encode_unlock_amount(0xFFFF) == <<0x02, 0xFF, 0xFF>>
    end

    test "0x100000000 → 5 bytes" do
      assert Stas3Builder.encode_unlock_amount(0x100000000) ==
               <<0x05, 0x00, 0x00, 0x00, 0x00, 0x01>>
    end

    test "0xFFFFFFFFFFFFFF → 7 bytes" do
      assert Stas3Builder.encode_unlock_amount(0xFFFFFFFFFFFFFF) ==
               <<0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>
    end

    test "0xFFFFFFFFFFFFFFFF → 8 bytes (max)" do
      assert Stas3Builder.encode_unlock_amount(0xFFFFFFFFFFFFFFFF) ==
               <<0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>
    end

    test "encoded payload length never exceeds 8 bytes for any 64-bit unsigned" do
      for amount <- [1, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x1FFFFFFFFFFFFFFF] do
        <<len, _payload::binary-size(len)>> = Stas3Builder.encode_unlock_amount(amount)
        assert len <= 8
      end
    end
  end
end
