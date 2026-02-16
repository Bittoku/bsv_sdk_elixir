defmodule BSV.Script.Opcodes do
  @moduledoc """
  Bitcoin script opcode definitions.

  All standard opcodes from OP_0 (0x00) through OP_INVALIDOPCODE (0xff).
  Includes opcode-to-name and name-to-opcode mappings for ASM output.
  """

  # Push value
  @op_0 0x00
  @op_false 0x00
  @op_pushdata1 0x4C
  @op_pushdata2 0x4D
  @op_pushdata4 0x4E
  @op_1negate 0x4F
  @op_reserved 0x50
  @op_1 0x51
  @op_true 0x51
  @op_2 0x52
  @op_3 0x53
  @op_4 0x54
  @op_5 0x55
  @op_6 0x56
  @op_7 0x57
  @op_8 0x58
  @op_9 0x59
  @op_10 0x5A
  @op_11 0x5B
  @op_12 0x5C
  @op_13 0x5D
  @op_14 0x5E
  @op_15 0x5F
  @op_16 0x60

  # Flow control
  @op_nop 0x61
  @op_ver 0x62
  @op_if 0x63
  @op_notif 0x64
  @op_verif 0x65
  @op_vernotif 0x66
  @op_else 0x67
  @op_endif 0x68
  @op_verify 0x69
  @op_return 0x6A

  # Stack
  @op_toaltstack 0x6B
  @op_fromaltstack 0x6C
  @op_2drop 0x6D
  @op_2dup 0x6E
  @op_3dup 0x6F
  @op_2over 0x70
  @op_2rot 0x71
  @op_2swap 0x72
  @op_ifdup 0x73
  @op_depth 0x74
  @op_drop 0x75
  @op_dup 0x76
  @op_nip 0x77
  @op_over 0x78
  @op_pick 0x79
  @op_roll 0x7A
  @op_rot 0x7B
  @op_swap 0x7C
  @op_tuck 0x7D

  # Splice
  @op_cat 0x7E
  @op_split 0x7F
  @op_num2bin 0x80
  @op_bin2num 0x81
  @op_size 0x82

  # Bitwise logic
  @op_invert 0x83
  @op_and 0x84
  @op_or 0x85
  @op_xor 0x86
  @op_equal 0x87
  @op_equalverify 0x88
  @op_reserved1 0x89
  @op_reserved2 0x8A

  # Arithmetic
  @op_1add 0x8B
  @op_1sub 0x8C
  @op_2mul 0x8D
  @op_2div 0x8E
  @op_negate 0x8F
  @op_abs 0x90
  @op_not 0x91
  @op_0notequal 0x92
  @op_add 0x93
  @op_sub 0x94
  @op_mul 0x95
  @op_div 0x96
  @op_mod 0x97
  @op_lshift 0x98
  @op_rshift 0x99
  @op_booland 0x9A
  @op_boolor 0x9B
  @op_numequal 0x9C
  @op_numequalverify 0x9D
  @op_numnotequal 0x9E
  @op_lessthan 0x9F
  @op_greaterthan 0xA0
  @op_lessthanorequal 0xA1
  @op_greaterthanorequal 0xA2
  @op_min 0xA3
  @op_max 0xA4
  @op_within 0xA5

  # Crypto
  @op_ripemd160 0xA6
  @op_sha1 0xA7
  @op_sha256 0xA8
  @op_hash160 0xA9
  @op_hash256 0xAA
  @op_codeseparator 0xAB
  @op_checksig 0xAC
  @op_checksigverify 0xAD
  @op_checkmultisig 0xAE
  @op_checkmultisigverify 0xAF

  # Locktime
  @op_nop1 0xB0
  @op_nop2 0xB1
  @op_nop3 0xB2
  @op_nop4 0xB3
  @op_nop5 0xB4
  @op_nop6 0xB5
  @op_nop7 0xB6
  @op_nop8 0xB7
  @op_nop9 0xB8
  @op_nop10 0xB9

  @op_invalidopcode 0xFF

  # Public accessors as macros
  defmacro op_0, do: @op_0
  defmacro op_false, do: @op_false
  defmacro op_pushdata1, do: @op_pushdata1
  defmacro op_pushdata2, do: @op_pushdata2
  defmacro op_pushdata4, do: @op_pushdata4
  defmacro op_1negate, do: @op_1negate
  defmacro op_reserved, do: @op_reserved
  defmacro op_1, do: @op_1
  defmacro op_true, do: @op_true
  defmacro op_2, do: @op_2
  defmacro op_3, do: @op_3
  defmacro op_4, do: @op_4
  defmacro op_5, do: @op_5
  defmacro op_6, do: @op_6
  defmacro op_7, do: @op_7
  defmacro op_8, do: @op_8
  defmacro op_9, do: @op_9
  defmacro op_10, do: @op_10
  defmacro op_11, do: @op_11
  defmacro op_12, do: @op_12
  defmacro op_13, do: @op_13
  defmacro op_14, do: @op_14
  defmacro op_15, do: @op_15
  defmacro op_16, do: @op_16
  defmacro op_nop, do: @op_nop
  defmacro op_ver, do: @op_ver
  defmacro op_if, do: @op_if
  defmacro op_notif, do: @op_notif
  defmacro op_verif, do: @op_verif
  defmacro op_vernotif, do: @op_vernotif
  defmacro op_else, do: @op_else
  defmacro op_endif, do: @op_endif
  defmacro op_verify, do: @op_verify
  defmacro op_return, do: @op_return
  defmacro op_toaltstack, do: @op_toaltstack
  defmacro op_fromaltstack, do: @op_fromaltstack
  defmacro op_2drop, do: @op_2drop
  defmacro op_2dup, do: @op_2dup
  defmacro op_3dup, do: @op_3dup
  defmacro op_2over, do: @op_2over
  defmacro op_2rot, do: @op_2rot
  defmacro op_2swap, do: @op_2swap
  defmacro op_ifdup, do: @op_ifdup
  defmacro op_depth, do: @op_depth
  defmacro op_drop, do: @op_drop
  defmacro op_dup, do: @op_dup
  defmacro op_nip, do: @op_nip
  defmacro op_over, do: @op_over
  defmacro op_pick, do: @op_pick
  defmacro op_roll, do: @op_roll
  defmacro op_rot, do: @op_rot
  defmacro op_swap, do: @op_swap
  defmacro op_tuck, do: @op_tuck
  defmacro op_cat, do: @op_cat
  defmacro op_split, do: @op_split
  defmacro op_num2bin, do: @op_num2bin
  defmacro op_bin2num, do: @op_bin2num
  defmacro op_size, do: @op_size
  defmacro op_invert, do: @op_invert
  defmacro op_and, do: @op_and
  defmacro op_or, do: @op_or
  defmacro op_xor, do: @op_xor
  defmacro op_equal, do: @op_equal
  defmacro op_equalverify, do: @op_equalverify
  defmacro op_reserved1, do: @op_reserved1
  defmacro op_reserved2, do: @op_reserved2
  defmacro op_1add, do: @op_1add
  defmacro op_1sub, do: @op_1sub
  defmacro op_2mul, do: @op_2mul
  defmacro op_2div, do: @op_2div
  defmacro op_negate, do: @op_negate
  defmacro op_abs, do: @op_abs
  defmacro op_not, do: @op_not
  defmacro op_0notequal, do: @op_0notequal
  defmacro op_add, do: @op_add
  defmacro op_sub, do: @op_sub
  defmacro op_mul, do: @op_mul
  defmacro op_div, do: @op_div
  defmacro op_mod, do: @op_mod
  defmacro op_lshift, do: @op_lshift
  defmacro op_rshift, do: @op_rshift
  defmacro op_booland, do: @op_booland
  defmacro op_boolor, do: @op_boolor
  defmacro op_numequal, do: @op_numequal
  defmacro op_numequalverify, do: @op_numequalverify
  defmacro op_numnotequal, do: @op_numnotequal
  defmacro op_lessthan, do: @op_lessthan
  defmacro op_greaterthan, do: @op_greaterthan
  defmacro op_lessthanorequal, do: @op_lessthanorequal
  defmacro op_greaterthanorequal, do: @op_greaterthanorequal
  defmacro op_min, do: @op_min
  defmacro op_max, do: @op_max
  defmacro op_within, do: @op_within
  defmacro op_ripemd160, do: @op_ripemd160
  defmacro op_sha1, do: @op_sha1
  defmacro op_sha256, do: @op_sha256
  defmacro op_hash160, do: @op_hash160
  defmacro op_hash256, do: @op_hash256
  defmacro op_codeseparator, do: @op_codeseparator
  defmacro op_checksig, do: @op_checksig
  defmacro op_checksigverify, do: @op_checksigverify
  defmacro op_checkmultisig, do: @op_checkmultisig
  defmacro op_checkmultisigverify, do: @op_checkmultisigverify
  defmacro op_nop1, do: @op_nop1
  defmacro op_nop2, do: @op_nop2
  defmacro op_nop3, do: @op_nop3
  defmacro op_nop4, do: @op_nop4
  defmacro op_nop5, do: @op_nop5
  defmacro op_nop6, do: @op_nop6
  defmacro op_nop7, do: @op_nop7
  defmacro op_nop8, do: @op_nop8
  defmacro op_nop9, do: @op_nop9
  defmacro op_nop10, do: @op_nop10
  defmacro op_invalidopcode, do: @op_invalidopcode

  @opcode_to_name_map %{
                        0x00 => "OP_0",
                        0x4C => "OP_PUSHDATA1",
                        0x4D => "OP_PUSHDATA2",
                        0x4E => "OP_PUSHDATA4",
                        0x4F => "OP_1NEGATE",
                        0x50 => "OP_RESERVED",
                        0x51 => "OP_1",
                        0x52 => "OP_2",
                        0x53 => "OP_3",
                        0x54 => "OP_4",
                        0x55 => "OP_5",
                        0x56 => "OP_6",
                        0x57 => "OP_7",
                        0x58 => "OP_8",
                        0x59 => "OP_9",
                        0x5A => "OP_10",
                        0x5B => "OP_11",
                        0x5C => "OP_12",
                        0x5D => "OP_13",
                        0x5E => "OP_14",
                        0x5F => "OP_15",
                        0x60 => "OP_16",
                        0x61 => "OP_NOP",
                        0x62 => "OP_VER",
                        0x63 => "OP_IF",
                        0x64 => "OP_NOTIF",
                        0x65 => "OP_VERIF",
                        0x66 => "OP_VERNOTIF",
                        0x67 => "OP_ELSE",
                        0x68 => "OP_ENDIF",
                        0x69 => "OP_VERIFY",
                        0x6A => "OP_RETURN",
                        0x6B => "OP_TOALTSTACK",
                        0x6C => "OP_FROMALTSTACK",
                        0x6D => "OP_2DROP",
                        0x6E => "OP_2DUP",
                        0x6F => "OP_3DUP",
                        0x70 => "OP_2OVER",
                        0x71 => "OP_2ROT",
                        0x72 => "OP_2SWAP",
                        0x73 => "OP_IFDUP",
                        0x74 => "OP_DEPTH",
                        0x75 => "OP_DROP",
                        0x76 => "OP_DUP",
                        0x77 => "OP_NIP",
                        0x78 => "OP_OVER",
                        0x79 => "OP_PICK",
                        0x7A => "OP_ROLL",
                        0x7B => "OP_ROT",
                        0x7C => "OP_SWAP",
                        0x7D => "OP_TUCK",
                        0x7E => "OP_CAT",
                        0x7F => "OP_SPLIT",
                        0x80 => "OP_NUM2BIN",
                        0x81 => "OP_BIN2NUM",
                        0x82 => "OP_SIZE",
                        0x83 => "OP_INVERT",
                        0x84 => "OP_AND",
                        0x85 => "OP_OR",
                        0x86 => "OP_XOR",
                        0x87 => "OP_EQUAL",
                        0x88 => "OP_EQUALVERIFY",
                        0x89 => "OP_RESERVED1",
                        0x8A => "OP_RESERVED2",
                        0x8B => "OP_1ADD",
                        0x8C => "OP_1SUB",
                        0x8D => "OP_2MUL",
                        0x8E => "OP_2DIV",
                        0x8F => "OP_NEGATE",
                        0x90 => "OP_ABS",
                        0x91 => "OP_NOT",
                        0x92 => "OP_0NOTEQUAL",
                        0x93 => "OP_ADD",
                        0x94 => "OP_SUB",
                        0x95 => "OP_MUL",
                        0x96 => "OP_DIV",
                        0x97 => "OP_MOD",
                        0x98 => "OP_LSHIFT",
                        0x99 => "OP_RSHIFT",
                        0x9A => "OP_BOOLAND",
                        0x9B => "OP_BOOLOR",
                        0x9C => "OP_NUMEQUAL",
                        0x9D => "OP_NUMEQUALVERIFY",
                        0x9E => "OP_NUMNOTEQUAL",
                        0x9F => "OP_LESSTHAN",
                        0xA0 => "OP_GREATERTHAN",
                        0xA1 => "OP_LESSTHANOREQUAL",
                        0xA2 => "OP_GREATERTHANOREQUAL",
                        0xA3 => "OP_MIN",
                        0xA4 => "OP_MAX",
                        0xA5 => "OP_WITHIN",
                        0xA6 => "OP_RIPEMD160",
                        0xA7 => "OP_SHA1",
                        0xA8 => "OP_SHA256",
                        0xA9 => "OP_HASH160",
                        0xAA => "OP_HASH256",
                        0xAB => "OP_CODESEPARATOR",
                        0xAC => "OP_CHECKSIG",
                        0xAD => "OP_CHECKSIGVERIFY",
                        0xAE => "OP_CHECKMULTISIG",
                        0xAF => "OP_CHECKMULTISIGVERIFY",
                        0xB0 => "OP_NOP1",
                        0xB1 => "OP_NOP2",
                        0xB2 => "OP_NOP3",
                        0xB3 => "OP_NOP4",
                        0xB4 => "OP_NOP5",
                        0xB5 => "OP_NOP6",
                        0xB6 => "OP_NOP7",
                        0xB7 => "OP_NOP8",
                        0xB8 => "OP_NOP9",
                        0xB9 => "OP_NOP10",
                        0xFF => "OP_INVALIDOPCODE"
                      }
                      |> Map.merge(Map.new(1..75, fn i -> {i, "OP_DATA_#{i}"} end))
                      |> Map.merge(Map.new(0xBA..0xF9, fn i -> {i, "OP_UNKNOWN#{i}"} end))
                      |> Map.put(0xFA, "OP_SMALLINTEGER")
                      |> Map.put(0xFB, "OP_PUBKEYS")
                      |> Map.put(0xFC, "OP_UNKNOWN252")
                      |> Map.put(0xFD, "OP_PUBKEYHASH")
                      |> Map.put(0xFE, "OP_PUBKEY")

  @name_to_opcode_map @opcode_to_name_map
                      |> Enum.map(fn {k, v} -> {v, k} end)
                      |> Map.new()
                      |> Map.merge(%{
                        "OP_FALSE" => 0x00,
                        "OP_TRUE" => 0x51,
                        "OP_ZERO" => 0x00,
                        "OP_ONE" => 0x51,
                        "OP_BASE" => 0x50,
                        "OP_LEFT" => 0x80,
                        "OP_RIGHT" => 0x81,
                        "OP_CHECKLOCKTIMEVERIFY" => 0xB1,
                        "OP_CHECKSEQUENCEVERIFY" => 0xB2
                      })

  @doc """
  Convert an opcode byte to its canonical name string.

  ## Examples

      iex> BSV.Script.Opcodes.opcode_to_name(0x76)
      "OP_DUP"
  """
  @spec opcode_to_name(byte()) :: String.t()
  def opcode_to_name(op) when is_integer(op) and op >= 0 and op <= 255 do
    Map.get(@opcode_to_name_map, op, "OP_UNKNOWN#{op}")
  end

  @doc """
  Convert an opcode name string to its byte value.

  ## Examples

      iex> BSV.Script.Opcodes.name_to_opcode("OP_DUP")
      {:ok, 0x76}
  """
  @spec name_to_opcode(String.t()) :: {:ok, byte()} | :error
  def name_to_opcode(name) when is_binary(name) do
    case Map.fetch(@name_to_opcode_map, name) do
      {:ok, _} = result -> result
      :error -> :error
    end
  end
end
