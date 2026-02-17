defmodule BSV.Tokens.Script.Templates do
  @moduledoc "Byte-pattern constants for classifying STAS script versions."

  @doc "STAS v2 prefix bytes: `OP_DUP OP_HASH160 OP_DATA_20`."
  def stas_v2_prefix, do: <<0x76, 0xA9, 0x14>>

  @doc "STAS v2 marker bytes after the 20-byte owner PKH."
  def stas_v2_marker, do: <<0x88, 0xAC, 0x69, 0x76, 0xAA, 0x60>>

  @doc "Byte offset of the owner PKH within a STAS v2 script."
  def stas_v2_owner_offset, do: 3
  @doc "Length of a public key hash in bytes."
  def pkh_len, do: 20
  @doc "Byte offset of the STAS v2 marker within the script."
  def stas_v2_marker_offset, do: 23
  @doc "Length of the STAS v2 template body in bytes."
  def stas_v2_template_len, do: 1431
  @doc "Byte offset of the OP_RETURN within a STAS v2 template."
  def stas_v2_op_return_offset, do: 1409
  @doc "Byte offset of the redemption PKH within a STAS v2 template."
  def stas_v2_redemption_offset, do: 1411
  @doc "Minimum length of a STAS v2 script (template + flags)."
  def stas_v2_min_len, do: 1432

  @doc "DSTAS base template prefix bytes."
  def dstas_base_prefix, do: <<0x6D, 0x82, 0x73, 0x63>>
  @doc "Length of the DSTAS base template in bytes."
  def dstas_base_template_len, do: 2812

  @doc "Standard P2PKH script length in bytes."
  def p2pkh_len, do: 25
  @doc "P2PKH script prefix: `OP_DUP OP_HASH160 OP_DATA_20`."
  def p2pkh_prefix, do: <<0x76, 0xA9, 0x14>>
  @doc "P2PKH script suffix: `OP_EQUALVERIFY OP_CHECKSIG`."
  def p2pkh_suffix, do: <<0x88, 0xAC>>
end
