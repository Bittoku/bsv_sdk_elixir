defmodule BSV.Tokens.Script.Templates do
  @moduledoc """
  Byte-pattern constants for classifying STAS script versions, plus
  builders for fixed locking-script bodies (such as the STAS 3.0 v0.1
  §10.2 P2MPKH locking script).
  """

  # STAS 3.0 v0.1 §10.2 fixed P2MPKH locking-script suffix — the constant
  # 47-byte body that follows `<OP_DUP OP_HASH160 <MPKH:20>>` to complete
  # the 70-byte locking script:
  #
  #   OP_EQUALVERIFY OP_SIZE 0x21 OP_EQUAL
  #   OP_IF OP_CHECKSIG OP_ELSE
  #     OP_1 OP_SPLIT
  #     (OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF) x 5
  #     OP_CHECKMULTISIG
  #   OP_ENDIF
  @p2mpkh_lock_suffix <<0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xAC, 0x67, 0x51, 0x7F, 0x51, 0x7F,
                        0x73, 0x63, 0x7C, 0x7F, 0x68, 0x51, 0x7F, 0x73, 0x63, 0x7C, 0x7F, 0x68,
                        0x51, 0x7F, 0x73, 0x63, 0x7C, 0x7F, 0x68, 0x51, 0x7F, 0x73, 0x63, 0x7C,
                        0x7F, 0x68, 0x51, 0x7F, 0x73, 0x63, 0x7C, 0x7F, 0x68, 0xAE, 0x68>>

  @doc """
  Build the fixed 70-byte STAS 3.0 v0.1 §10.2 P2MPKH locking-script body.

  This locking script is used at issuance and redemption boundaries of a
  STAS token — i.e. on UTXOs that are not themselves STAS in-life UTXOs
  but bracket a STAS token's lifecycle. In-life STAS UTXOs do NOT carry
  this script; the engine inlines equivalent logic.

  ## Input
  - `mpkh` — 20-byte MPKH (`HASH160` of the redeem buffer; see
    `BSV.Transaction.P2MPKH.mpkh/1`).

  ## Output
  70-byte binary equal to:

      <<0x76, 0xA9, 0x14, mpkh::binary-size(20),
        0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xAC, 0x67,
        0x51, 0x7F, (0x51, 0x7F, 0x73, 0x63, 0x7C, 0x7F, 0x68) x 5,
        0xAE, 0x68>>

  Decoded as Bitcoin Script: `OP_DUP OP_HASH160 <MPKH> OP_EQUALVERIFY
  OP_SIZE 0x21 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE OP_1 OP_SPLIT
  (OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF) x 5
  OP_CHECKMULTISIG OP_ENDIF`.
  """
  @spec p2mpkh_locking_script(<<_::160>>) :: binary()
  def p2mpkh_locking_script(<<mpkh::binary-size(20)>>) do
    <<0x76, 0xA9, 0x14, mpkh::binary, @p2mpkh_lock_suffix::binary>>
  end

  @doc "STAS 3.0 v0.1 §10.2 P2MPKH locking-script body length (70 bytes)."
  def p2mpkh_locking_script_len, do: 70

  @doc "EMPTY_HASH160 sentinel = HASH160(\"\"). Means \"skip auth\" in owner / arbitrator slots."
  def empty_hash160 do
    <<0xB4, 0x72, 0xA2, 0x66, 0xD0, 0xBD, 0x89, 0xC1, 0x37, 0x06, 0xA4, 0x13, 0x2C, 0xCF, 0xB1,
      0x6F, 0x7C, 0x3B, 0x9F, 0xCB>>
  end

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

  @doc "STAS 3.0 base template prefix bytes."
  def stas3_base_prefix, do: <<0x6D, 0x82, 0x73, 0x63>>
  @doc "Length of the STAS 3.0 base template in bytes."
  def stas3_base_template_len, do: 2812

  @doc "Standard P2PKH script length in bytes."
  def p2pkh_len, do: 25
  @doc "P2PKH script prefix: `OP_DUP OP_HASH160 OP_DATA_20`."
  def p2pkh_prefix, do: <<0x76, 0xA9, 0x14>>
  @doc "P2PKH script suffix: `OP_EQUALVERIFY OP_CHECKSIG`."
  def p2pkh_suffix, do: <<0x88, 0xAC>>
end
