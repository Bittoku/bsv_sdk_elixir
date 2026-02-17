defmodule BSV.Tokens.Script.StasBtgBuilder do
  @moduledoc """
  Builder for STAS-BTG (Back-to-Genesis) locking scripts.

  The STAS-BTG template extends the standard STAS v2 template with a
  dual-path spending mechanism:

  ## Path A — BTG Proof (OP_IF branch)
  The unlocking script pushes `<sig> <pubkey> <prefix> <output> <suffix> OP_TRUE`.
  The BTG preamble verifies the prev-TX proof.

  ## Path B — Checkpoint Attestation (OP_ELSE branch)
  The unlocking script pushes `<sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE`.
  The checkpoint gate verifies the issuer's co-signature.
  """

  alias BSV.Script

  @stas_v2_template_hex "76a914000000000000000000000000000000000000000088ac6976aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d976e7c5296a06394677768827601249301307c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027e7c7e7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad547f7701207f01207f7701247f517f7801007e8102fd00a063546752687f7801007e817f727e7b01177f777b557a766471567a577a786354807e7e676d68aa880067765158a569765187645294567a5379587a7e7e78637c8c7c53797e577a7e6878637c8c7c53797e577a7e6878637c8c7c53797e577a7e6878637c8c7c53797e577a7e6878637c8c7c53797e577a7e6867567a6876aa587a7d54807e577a597a5a7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa587a7d877663516752687c72879b69537a647500687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e817602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75537f7c0376a9148801147f775379645579887567726881766968789263556753687a76026c057f7701147f8263517f7c766301007e817f7c6775006877686b537992635379528763547a6b547a6b677c6b567a6b537a7c717c71716868547a587f7c81547a557964936755795187637c686b687c547f7701207f75748c7a7669765880748c7a76567a876457790376a9147e7c7e557967041976a9147c7e0288ac687e7e5579636c766976748c7a9d58807e6c0376a9147e748c7a7e6c7e7e676c766b8263828c007c80517e846864745aa0637c748c7a76697d937b7b58807e56790376a9147e748c7a7e55797e7e6868686c567a5187637500678263828c007c80517e846868647459a0637c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e687459a0637c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e68687c537a9d547963557958807e041976a91455797e0288ac7e7e68aa87726d77776a140000000000000000000000000000000000000000"

  @doc """
  Build a STAS-BTG locking script with dual-path spending.

  ## Parameters
  - `owner_pkh` - 20-byte public key hash of the owner
  - `redemption_pkh` - 20-byte public key hash for redemption / token ID
  - `splittable` - whether the token can be split

  ## Returns
  `{:ok, Script.t()}` containing the STAS-BTG locking script.
  """
  @spec build_stas_btg_locking_script(<<_::160>>, <<_::160>>, boolean()) ::
          {:ok, Script.t()} | {:error, term()}
  def build_stas_btg_locking_script(
        <<owner_pkh::binary-size(20)>>,
        <<redemption_pkh::binary-size(20)>>,
        splittable
      ) do
    preamble = build_btg_preamble(redemption_pkh)
    checkpoint_gate = build_checkpoint_gate(redemption_pkh)

    {:ok, stas_body} = build_stas_v2_body(owner_pkh, redemption_pkh, splittable)

    # OP_IF [preamble] OP_ELSE [checkpoint gate] OP_ENDIF [stas v2 body]
    script_bin =
      <<0x63>> <>
        preamble <>
        <<0x67>> <>
        checkpoint_gate <>
        <<0x68>> <>
        stas_body

    Script.from_binary(script_bin)
  end

  @doc """
  Build the checkpoint attestation gate bytes.

  Gate performs: OP_DUP OP_HASH160 push_20(redemption_pkh) OP_EQUALVERIFY OP_CHECKSIGVERIFY
  Total: 25 bytes.
  """
  @spec build_checkpoint_gate(<<_::160>>) :: binary()
  def build_checkpoint_gate(<<redemption_pkh::binary-size(20)>>) do
    <<0x76, 0xA9, 0x14>> <> redemption_pkh <> <<0x88, 0xAD>>
  end

  @doc """
  Find the byte offset of the redemption PKH within the BTG preamble.

  Scans for the pattern: 0x14 (push 20 bytes) + 20 bytes + 0x88 (OP_EQUALVERIFY)
  within the first 350 bytes of the script.
  """
  @spec find_preamble_redemption_offset(binary()) :: non_neg_integer() | nil
  def find_preamble_redemption_offset(script) when is_binary(script) do
    if byte_size(script) < 22 do
      nil
    else
      scan_for_redemption(script, 0, min(byte_size(script) - 22, 350))
    end
  end

  @doc """
  Push a number onto a script using minimal encoding.
  """
  @spec push_number(integer()) :: binary()
  def push_number(0), do: <<0x00>>
  def push_number(-1), do: <<0x4F>>

  def push_number(value) when value >= 1 and value <= 16 do
    <<0x50 + value>>
  end

  def push_number(value) do
    negative = value < 0
    abs_val = abs(value)

    bytes = encode_script_number(abs_val, [])

    bytes =
      case List.last(bytes) do
        b when Bitwise.band(b, 0x80) != 0 ->
          bytes ++ [if(negative, do: 0x80, else: 0x00)]

        _ when negative ->
          {init, [last]} = Enum.split(bytes, -1)
          init ++ [Bitwise.bor(last, 0x80)]

        _ ->
          bytes
      end

    data = :erlang.list_to_binary(bytes)
    len = byte_size(data)

    cond do
      len <= 75 -> <<len::8>> <> data
      len <= 255 -> <<0x4C, len::8>> <> data
      true -> <<0x4D, len::little-16>> <> data
    end
  end

  # ---- Private ----

  defp encode_script_number(0, []), do: [0]
  defp encode_script_number(0, acc), do: acc

  defp encode_script_number(val, acc) do
    encode_script_number(Bitwise.bsr(val, 8), acc ++ [Bitwise.band(val, 0xFF)])
  end

  defp build_btg_preamble(redemption_pkh) do
    # Stack: sig pubkey prefix output suffix  (suffix on top)
    # Indices: [4] [3] [2] [1] [0]

    # Step 1: Reconstruct prev TX and hash
    # Copy prefix (idx 2) to top
    <<0x52, 0x79>> <>
      # Copy output (now idx 2) to top
      <<0x52, 0x79>> <>
      # OP_CAT: prefix' || output'
      <<0x7E>> <>
      # Copy suffix (now idx 1) to top
      <<0x51, 0x79>> <>
      # OP_CAT: (prefix'||output') || suffix'
      <<0x7E>> <>
      # OP_HASH256: double-SHA256
      <<0xAA>> <>
      # OP_TOALTSTACK: stash prev_tx_hash
      <<0x6B>> <>
      # Step 2: Extract satoshis from output
      # Copy output (idx 1) to top
      <<0x51, 0x79>> <>
      # Split at byte 8: [satoshis | rest_of_output]
      <<0x01, 0x08, 0x7F>> <>
      # OP_TOALTSTACK rest_of_output
      <<0x6B>> <>
      # OP_BIN2NUM satoshis
      <<0x81>> <>
      # OP_TOALTSTACK satoshis_num
      <<0x6B>> <>
      # Step 3: Verify locking script format
      # OP_FROMALTSTACK rest_of_output
      <<0x6C>> <>
      # Split first byte (varint indicator)
      <<0x51, 0x7F>> <>
      # OP_SWAP
      <<0x7C>> <>
      # Push 0xfd, OP_EQUAL
      <<0x01, 0xFD, 0x87>> <>
      # OP_IF: varint == 0xfd → skip 2 more bytes
      <<0x63>> <>
      <<0x52, 0x7F, 0x75>> <>
      # OP_ENDIF
      <<0x68>> <>
      # Split first 3 bytes (76 a9 14 prefix)
      <<0x53, 0x7F>> <>
      # OP_SWAP
      <<0x7C>> <>
      # Push expected prefix 76 a9 14
      <<0x03, 0x76, 0xA9, 0x14>> <>
      # OP_EQUALVERIFY
      <<0x88>> <>
      # Check script length to determine STAS-BTG vs P2PKH
      # OP_SIZE
      <<0x82>> <>
      # Push 22, OP_EQUAL
      <<0x01, 22, 0x87>> <>
      # OP_IF (P2PKH path)
      <<0x63>> <>
      # Split 20 bytes PKH
      <<0x01, 20, 0x7F>> <>
      # OP_DROP (88ac suffix)
      <<0x75>> <>
      # OP_ELSE (STAS-BTG path)
      <<0x67>> <>
      # Split at offset 1408 (1411 - 3 bytes prefix already stripped)
      push_number(1408) <>
      # OP_SPLIT
      <<0x7F>> <>
      # OP_NIP (drop before_1408)
      <<0x77>> <>
      # Split 20 bytes redemption PKH
      <<0x01, 20, 0x7F>> <>
      # OP_DROP (remainder)
      <<0x75>> <>
      # OP_ENDIF
      <<0x68>> <>
      # Push expected redemption PKH and verify
      <<0x14>> <>
      redemption_pkh <>
      # OP_EQUALVERIFY
      <<0x88>> <>
      # Step 4: Drop proof items, recover stashed values
      # OP_DROP suffix, OP_DROP output, OP_DROP prefix
      <<0x75, 0x75, 0x75>> <>
      # OP_FROMALTSTACK satoshis_num, OP_FROMALTSTACK prev_tx_hash
      <<0x6C, 0x6C>> <>
      # OP_TOALTSTACK prev_tx_hash, OP_TOALTSTACK satoshis_num
      <<0x6B, 0x6B>>
  end

  defp build_stas_v2_body(owner_pkh, redemption_pkh, splittable) do
    {:ok, template} = Base.decode16(@stas_v2_template_hex, case: :mixed)

    # Patch owner PKH at bytes 3..23
    <<prefix::binary-size(3), _old_owner::binary-size(20), rest::binary>> = template
    template = prefix <> owner_pkh <> rest

    # Patch redemption PKH at bytes 1411..1431
    <<before_redemption::binary-size(1411), _old_redemption::binary-size(20)>> = template
    template = before_redemption <> redemption_pkh

    # Append flags
    flags_byte = if splittable, do: 0x00, else: 0x01
    {:ok, template <> <<0x01, flags_byte>>}
  end

  defp scan_for_redemption(_script, offset, max_offset) when offset > max_offset, do: nil

  defp scan_for_redemption(script, offset, max_offset) do
    if :binary.at(script, offset) == 0x14 and
         offset + 21 < byte_size(script) and
         :binary.at(script, offset + 21) == 0x88 do
      offset + 1
    else
      scan_for_redemption(script, offset + 1, max_offset)
    end
  end
end
