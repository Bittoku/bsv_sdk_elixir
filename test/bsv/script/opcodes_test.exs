defmodule BSV.Script.OpcodesTest do
  use ExUnit.Case, async: true

  alias BSV.Script.Opcodes

  describe "opcode_to_name/1" do
    test "returns correct names for common opcodes" do
      assert Opcodes.opcode_to_name(0x76) == "OP_DUP"
      assert Opcodes.opcode_to_name(0xA9) == "OP_HASH160"
      assert Opcodes.opcode_to_name(0x88) == "OP_EQUALVERIFY"
      assert Opcodes.opcode_to_name(0xAC) == "OP_CHECKSIG"
      assert Opcodes.opcode_to_name(0x00) == "OP_0"
      assert Opcodes.opcode_to_name(0x51) == "OP_1"
      assert Opcodes.opcode_to_name(0x6A) == "OP_RETURN"
    end

    test "returns OP_DATA_N for push opcodes" do
      assert Opcodes.opcode_to_name(0x01) == "OP_DATA_1"
      assert Opcodes.opcode_to_name(0x14) == "OP_DATA_20"
      assert Opcodes.opcode_to_name(0x4B) == "OP_DATA_75"
    end

    test "returns names for NOP opcodes" do
      assert Opcodes.opcode_to_name(0xB0) == "OP_NOP1"
      assert Opcodes.opcode_to_name(0xB9) == "OP_NOP10"
    end

    test "returns names for all number opcodes" do
      assert Opcodes.opcode_to_name(0x52) == "OP_2"
      assert Opcodes.opcode_to_name(0x60) == "OP_16"
      assert Opcodes.opcode_to_name(0x4F) == "OP_1NEGATE"
    end

    test "returns names for flow control" do
      assert Opcodes.opcode_to_name(0x63) == "OP_IF"
      assert Opcodes.opcode_to_name(0x64) == "OP_NOTIF"
      assert Opcodes.opcode_to_name(0x67) == "OP_ELSE"
      assert Opcodes.opcode_to_name(0x68) == "OP_ENDIF"
      assert Opcodes.opcode_to_name(0x69) == "OP_VERIFY"
    end

    test "returns names for stack opcodes" do
      assert Opcodes.opcode_to_name(0x6B) == "OP_TOALTSTACK"
      assert Opcodes.opcode_to_name(0x6C) == "OP_FROMALTSTACK"
      assert Opcodes.opcode_to_name(0x6D) == "OP_2DROP"
      assert Opcodes.opcode_to_name(0x6E) == "OP_2DUP"
      assert Opcodes.opcode_to_name(0x6F) == "OP_3DUP"
      assert Opcodes.opcode_to_name(0x70) == "OP_2OVER"
      assert Opcodes.opcode_to_name(0x71) == "OP_2ROT"
      assert Opcodes.opcode_to_name(0x72) == "OP_2SWAP"
      assert Opcodes.opcode_to_name(0x73) == "OP_IFDUP"
      assert Opcodes.opcode_to_name(0x74) == "OP_DEPTH"
      assert Opcodes.opcode_to_name(0x75) == "OP_DROP"
      assert Opcodes.opcode_to_name(0x77) == "OP_NIP"
      assert Opcodes.opcode_to_name(0x78) == "OP_OVER"
      assert Opcodes.opcode_to_name(0x79) == "OP_PICK"
      assert Opcodes.opcode_to_name(0x7A) == "OP_ROLL"
      assert Opcodes.opcode_to_name(0x7B) == "OP_ROT"
      assert Opcodes.opcode_to_name(0x7C) == "OP_SWAP"
      assert Opcodes.opcode_to_name(0x7D) == "OP_TUCK"
    end

    test "returns names for splice opcodes" do
      assert Opcodes.opcode_to_name(0x7E) == "OP_CAT"
      assert Opcodes.opcode_to_name(0x7F) == "OP_SPLIT"
      assert Opcodes.opcode_to_name(0x80) == "OP_NUM2BIN"
      assert Opcodes.opcode_to_name(0x81) == "OP_BIN2NUM"
      assert Opcodes.opcode_to_name(0x82) == "OP_SIZE"
    end

    test "returns names for bitwise opcodes" do
      assert Opcodes.opcode_to_name(0x83) == "OP_INVERT"
      assert Opcodes.opcode_to_name(0x84) == "OP_AND"
      assert Opcodes.opcode_to_name(0x85) == "OP_OR"
      assert Opcodes.opcode_to_name(0x86) == "OP_XOR"
      assert Opcodes.opcode_to_name(0x87) == "OP_EQUAL"
      assert Opcodes.opcode_to_name(0x88) == "OP_EQUALVERIFY"
    end

    test "returns names for arithmetic opcodes" do
      assert Opcodes.opcode_to_name(0x8B) == "OP_1ADD"
      assert Opcodes.opcode_to_name(0x8C) == "OP_1SUB"
      assert Opcodes.opcode_to_name(0x8F) == "OP_NEGATE"
      assert Opcodes.opcode_to_name(0x90) == "OP_ABS"
      assert Opcodes.opcode_to_name(0x91) == "OP_NOT"
      assert Opcodes.opcode_to_name(0x92) == "OP_0NOTEQUAL"
      assert Opcodes.opcode_to_name(0x93) == "OP_ADD"
      assert Opcodes.opcode_to_name(0x94) == "OP_SUB"
      assert Opcodes.opcode_to_name(0x95) == "OP_MUL"
      assert Opcodes.opcode_to_name(0x96) == "OP_DIV"
      assert Opcodes.opcode_to_name(0x97) == "OP_MOD"
      assert Opcodes.opcode_to_name(0x98) == "OP_LSHIFT"
      assert Opcodes.opcode_to_name(0x99) == "OP_RSHIFT"
      assert Opcodes.opcode_to_name(0x9A) == "OP_BOOLAND"
      assert Opcodes.opcode_to_name(0x9B) == "OP_BOOLOR"
      assert Opcodes.opcode_to_name(0x9C) == "OP_NUMEQUAL"
      assert Opcodes.opcode_to_name(0x9D) == "OP_NUMEQUALVERIFY"
      assert Opcodes.opcode_to_name(0x9E) == "OP_NUMNOTEQUAL"
      assert Opcodes.opcode_to_name(0x9F) == "OP_LESSTHAN"
      assert Opcodes.opcode_to_name(0xA0) == "OP_GREATERTHAN"
      assert Opcodes.opcode_to_name(0xA1) == "OP_LESSTHANOREQUAL"
      assert Opcodes.opcode_to_name(0xA2) == "OP_GREATERTHANOREQUAL"
      assert Opcodes.opcode_to_name(0xA3) == "OP_MIN"
      assert Opcodes.opcode_to_name(0xA4) == "OP_MAX"
      assert Opcodes.opcode_to_name(0xA5) == "OP_WITHIN"
    end

    test "returns names for crypto opcodes" do
      assert Opcodes.opcode_to_name(0xA6) == "OP_RIPEMD160"
      assert Opcodes.opcode_to_name(0xA7) == "OP_SHA1"
      assert Opcodes.opcode_to_name(0xA8) == "OP_SHA256"
      assert Opcodes.opcode_to_name(0xA9) == "OP_HASH160"
      assert Opcodes.opcode_to_name(0xAA) == "OP_HASH256"
      assert Opcodes.opcode_to_name(0xAB) == "OP_CODESEPARATOR"
      assert Opcodes.opcode_to_name(0xAC) == "OP_CHECKSIG"
      assert Opcodes.opcode_to_name(0xAD) == "OP_CHECKSIGVERIFY"
      assert Opcodes.opcode_to_name(0xAE) == "OP_CHECKMULTISIG"
      assert Opcodes.opcode_to_name(0xAF) == "OP_CHECKMULTISIGVERIFY"
    end

    test "returns names for pushdata opcodes" do
      assert Opcodes.opcode_to_name(0x4C) == "OP_PUSHDATA1"
      assert Opcodes.opcode_to_name(0x4D) == "OP_PUSHDATA2"
      assert Opcodes.opcode_to_name(0x4E) == "OP_PUSHDATA4"
    end

    test "returns names for reserved opcodes" do
      assert Opcodes.opcode_to_name(0x50) == "OP_RESERVED"
      assert Opcodes.opcode_to_name(0x62) == "OP_VER"
      assert Opcodes.opcode_to_name(0x65) == "OP_VERIF"
      assert Opcodes.opcode_to_name(0x66) == "OP_VERNOTIF"
      assert Opcodes.opcode_to_name(0x89) == "OP_RESERVED1"
      assert Opcodes.opcode_to_name(0x8A) == "OP_RESERVED2"
    end

    test "returns names for special high opcodes" do
      assert Opcodes.opcode_to_name(0xFA) == "OP_SMALLINTEGER"
      assert Opcodes.opcode_to_name(0xFB) == "OP_PUBKEYS"
      assert Opcodes.opcode_to_name(0xFD) == "OP_PUBKEYHASH"
      assert Opcodes.opcode_to_name(0xFE) == "OP_PUBKEY"
      assert Opcodes.opcode_to_name(0xFF) == "OP_INVALIDOPCODE"
    end

    test "returns OP_UNKNOWN for undefined high range" do
      assert Opcodes.opcode_to_name(0xBA) =~ "OP_UNKNOWN"
      assert Opcodes.opcode_to_name(0xF9) =~ "OP_UNKNOWN"
    end

    test "returns OP_2MUL and OP_2DIV" do
      assert Opcodes.opcode_to_name(0x8D) == "OP_2MUL"
      assert Opcodes.opcode_to_name(0x8E) == "OP_2DIV"
    end
  end

  describe "name_to_opcode/1" do
    test "returns correct byte for common names" do
      assert Opcodes.name_to_opcode("OP_DUP") == {:ok, 0x76}
      assert Opcodes.name_to_opcode("OP_HASH160") == {:ok, 0xA9}
      assert Opcodes.name_to_opcode("OP_CHECKSIG") == {:ok, 0xAC}
    end

    test "supports aliases" do
      assert Opcodes.name_to_opcode("OP_FALSE") == {:ok, 0x00}
      assert Opcodes.name_to_opcode("OP_TRUE") == {:ok, 0x51}
      assert Opcodes.name_to_opcode("OP_0") == {:ok, 0x00}
      assert Opcodes.name_to_opcode("OP_ONE") == {:ok, 0x51}
      assert Opcodes.name_to_opcode("OP_ZERO") == {:ok, 0x00}
      assert Opcodes.name_to_opcode("OP_BASE") == {:ok, 0x50}
    end

    test "supports locktime aliases" do
      assert Opcodes.name_to_opcode("OP_CHECKLOCKTIMEVERIFY") == {:ok, 0xB1}
      assert Opcodes.name_to_opcode("OP_CHECKSEQUENCEVERIFY") == {:ok, 0xB2}
    end

    test "supports LEFT/RIGHT aliases" do
      assert Opcodes.name_to_opcode("OP_LEFT") == {:ok, 0x80}
      assert Opcodes.name_to_opcode("OP_RIGHT") == {:ok, 0x81}
    end

    test "returns :error for unknown names" do
      assert Opcodes.name_to_opcode("OP_BOGUS") == :error
    end

    test "returns correct byte for all arithmetic names" do
      assert Opcodes.name_to_opcode("OP_ADD") == {:ok, 0x93}
      assert Opcodes.name_to_opcode("OP_SUB") == {:ok, 0x94}
      assert Opcodes.name_to_opcode("OP_MUL") == {:ok, 0x95}
      assert Opcodes.name_to_opcode("OP_DIV") == {:ok, 0x96}
      assert Opcodes.name_to_opcode("OP_MOD") == {:ok, 0x97}
      assert Opcodes.name_to_opcode("OP_1ADD") == {:ok, 0x8B}
      assert Opcodes.name_to_opcode("OP_1SUB") == {:ok, 0x8C}
      assert Opcodes.name_to_opcode("OP_NEGATE") == {:ok, 0x8F}
      assert Opcodes.name_to_opcode("OP_ABS") == {:ok, 0x90}
    end

    test "returns correct byte for flow control" do
      assert Opcodes.name_to_opcode("OP_IF") == {:ok, 0x63}
      assert Opcodes.name_to_opcode("OP_NOTIF") == {:ok, 0x64}
      assert Opcodes.name_to_opcode("OP_ELSE") == {:ok, 0x67}
      assert Opcodes.name_to_opcode("OP_ENDIF") == {:ok, 0x68}
      assert Opcodes.name_to_opcode("OP_VERIFY") == {:ok, 0x69}
      assert Opcodes.name_to_opcode("OP_RETURN") == {:ok, 0x6A}
      assert Opcodes.name_to_opcode("OP_NOP") == {:ok, 0x61}
    end

    test "returns correct byte for NOP1-10" do
      assert Opcodes.name_to_opcode("OP_NOP1") == {:ok, 0xB0}
      assert Opcodes.name_to_opcode("OP_NOP2") == {:ok, 0xB1}
      assert Opcodes.name_to_opcode("OP_NOP10") == {:ok, 0xB9}
    end

    test "returns correct byte for data push names" do
      assert Opcodes.name_to_opcode("OP_DATA_1") == {:ok, 0x01}
      assert Opcodes.name_to_opcode("OP_DATA_20") == {:ok, 0x14}
      assert Opcodes.name_to_opcode("OP_DATA_75") == {:ok, 0x4B}
    end

    test "returns correct byte for pushdata names" do
      assert Opcodes.name_to_opcode("OP_PUSHDATA1") == {:ok, 0x4C}
      assert Opcodes.name_to_opcode("OP_PUSHDATA2") == {:ok, 0x4D}
      assert Opcodes.name_to_opcode("OP_PUSHDATA4") == {:ok, 0x4E}
    end
  end

  describe "macros" do
    # Test that macros resolve to correct values at compile time
    require Opcodes

    test "op_0 macro" do
      assert Opcodes.op_0() == 0x00
      assert Opcodes.op_false() == 0x00
    end

    test "op_1 macro" do
      assert Opcodes.op_1() == 0x51
      assert Opcodes.op_true() == 0x51
    end

    test "number macros" do
      assert Opcodes.op_2() == 0x52
      assert Opcodes.op_3() == 0x53
      assert Opcodes.op_16() == 0x60
      assert Opcodes.op_1negate() == 0x4F
    end

    test "flow control macros" do
      assert Opcodes.op_nop() == 0x61
      assert Opcodes.op_if() == 0x63
      assert Opcodes.op_notif() == 0x64
      assert Opcodes.op_else() == 0x67
      assert Opcodes.op_endif() == 0x68
      assert Opcodes.op_verify() == 0x69
      assert Opcodes.op_return() == 0x6A
    end

    test "stack macros" do
      assert Opcodes.op_toaltstack() == 0x6B
      assert Opcodes.op_fromaltstack() == 0x6C
      assert Opcodes.op_dup() == 0x76
      assert Opcodes.op_drop() == 0x75
      assert Opcodes.op_swap() == 0x7C
      assert Opcodes.op_rot() == 0x7B
      assert Opcodes.op_over() == 0x78
      assert Opcodes.op_nip() == 0x77
      assert Opcodes.op_tuck() == 0x7D
      assert Opcodes.op_pick() == 0x79
      assert Opcodes.op_roll() == 0x7A
      assert Opcodes.op_2drop() == 0x6D
      assert Opcodes.op_2dup() == 0x6E
      assert Opcodes.op_3dup() == 0x6F
      assert Opcodes.op_2over() == 0x70
      assert Opcodes.op_2rot() == 0x71
      assert Opcodes.op_2swap() == 0x72
      assert Opcodes.op_ifdup() == 0x73
      assert Opcodes.op_depth() == 0x74
    end

    test "splice macros" do
      assert Opcodes.op_cat() == 0x7E
      assert Opcodes.op_split() == 0x7F
      assert Opcodes.op_num2bin() == 0x80
      assert Opcodes.op_bin2num() == 0x81
      assert Opcodes.op_size() == 0x82
    end

    test "bitwise macros" do
      assert Opcodes.op_invert() == 0x83
      assert Opcodes.op_and() == 0x84
      assert Opcodes.op_or() == 0x85
      assert Opcodes.op_xor() == 0x86
      assert Opcodes.op_equal() == 0x87
      assert Opcodes.op_equalverify() == 0x88
    end

    test "arithmetic macros" do
      assert Opcodes.op_1add() == 0x8B
      assert Opcodes.op_1sub() == 0x8C
      assert Opcodes.op_2mul() == 0x8D
      assert Opcodes.op_2div() == 0x8E
      assert Opcodes.op_negate() == 0x8F
      assert Opcodes.op_abs() == 0x90
      assert Opcodes.op_not() == 0x91
      assert Opcodes.op_0notequal() == 0x92
      assert Opcodes.op_add() == 0x93
      assert Opcodes.op_sub() == 0x94
      assert Opcodes.op_mul() == 0x95
      assert Opcodes.op_div() == 0x96
      assert Opcodes.op_mod() == 0x97
      assert Opcodes.op_lshift() == 0x98
      assert Opcodes.op_rshift() == 0x99
      assert Opcodes.op_booland() == 0x9A
      assert Opcodes.op_boolor() == 0x9B
      assert Opcodes.op_numequal() == 0x9C
      assert Opcodes.op_numequalverify() == 0x9D
      assert Opcodes.op_numnotequal() == 0x9E
      assert Opcodes.op_lessthan() == 0x9F
      assert Opcodes.op_greaterthan() == 0xA0
      assert Opcodes.op_lessthanorequal() == 0xA1
      assert Opcodes.op_greaterthanorequal() == 0xA2
      assert Opcodes.op_min() == 0xA3
      assert Opcodes.op_max() == 0xA4
      assert Opcodes.op_within() == 0xA5
    end

    test "crypto macros" do
      assert Opcodes.op_ripemd160() == 0xA6
      assert Opcodes.op_sha1() == 0xA7
      assert Opcodes.op_sha256() == 0xA8
      assert Opcodes.op_hash160() == 0xA9
      assert Opcodes.op_hash256() == 0xAA
      assert Opcodes.op_codeseparator() == 0xAB
      assert Opcodes.op_checksig() == 0xAC
      assert Opcodes.op_checksigverify() == 0xAD
      assert Opcodes.op_checkmultisig() == 0xAE
      assert Opcodes.op_checkmultisigverify() == 0xAF
    end

    test "nop macros" do
      assert Opcodes.op_nop1() == 0xB0
      assert Opcodes.op_nop2() == 0xB1
      assert Opcodes.op_nop3() == 0xB2
      assert Opcodes.op_nop4() == 0xB3
      assert Opcodes.op_nop5() == 0xB4
      assert Opcodes.op_nop6() == 0xB5
      assert Opcodes.op_nop7() == 0xB6
      assert Opcodes.op_nop8() == 0xB7
      assert Opcodes.op_nop9() == 0xB8
      assert Opcodes.op_nop10() == 0xB9
    end

    test "special macros" do
      assert Opcodes.op_pushdata1() == 0x4C
      assert Opcodes.op_pushdata2() == 0x4D
      assert Opcodes.op_pushdata4() == 0x4E
      assert Opcodes.op_reserved() == 0x50
      assert Opcodes.op_ver() == 0x62
      assert Opcodes.op_verif() == 0x65
      assert Opcodes.op_vernotif() == 0x66
      assert Opcodes.op_reserved1() == 0x89
      assert Opcodes.op_reserved2() == 0x8A
      assert Opcodes.op_invalidopcode() == 0xFF
    end

    test "number macros 4-15" do
      assert Opcodes.op_4() == 0x54
      assert Opcodes.op_5() == 0x55
      assert Opcodes.op_6() == 0x56
      assert Opcodes.op_7() == 0x57
      assert Opcodes.op_8() == 0x58
      assert Opcodes.op_9() == 0x59
      assert Opcodes.op_10() == 0x5A
      assert Opcodes.op_11() == 0x5B
      assert Opcodes.op_12() == 0x5C
      assert Opcodes.op_13() == 0x5D
      assert Opcodes.op_14() == 0x5E
      assert Opcodes.op_15() == 0x5F
    end
  end
end
