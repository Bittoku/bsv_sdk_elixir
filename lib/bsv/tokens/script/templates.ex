defmodule BSV.Tokens.Script.Templates do
  @moduledoc "Byte-pattern constants for classifying STAS script versions."

  # STAS v2 prefix: OP_DUP OP_HASH160 OP_DATA_20
  def stas_v2_prefix, do: <<0x76, 0xA9, 0x14>>

  # Bytes after 20-byte owner PKH: OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY OP_DUP OP_HASH160 OP_16
  def stas_v2_marker, do: <<0x88, 0xAC, 0x69, 0x76, 0xAA, 0x60>>

  def stas_v2_owner_offset, do: 3
  def pkh_len, do: 20
  def stas_v2_marker_offset, do: 23
  def stas_v2_template_len, do: 1431
  def stas_v2_op_return_offset, do: 1409
  def stas_v2_redemption_offset, do: 1411
  def stas_v2_min_len, do: 1432

  # DSTAS base template prefix: OP_2MUL OP_SIZE OP_OVER OP_IF
  def dstas_base_prefix, do: <<0x6D, 0x82, 0x73, 0x63>>
  def dstas_base_template_len, do: 2812

  def p2pkh_len, do: 25
  def p2pkh_prefix, do: <<0x76, 0xA9, 0x14>>
  def p2pkh_suffix, do: <<0x88, 0xAC>>
end
