defmodule BSV.Tokens.Script.Stas3Builder do
  @moduledoc "Builder for STAS 3.0 (stas3-freeze-multisig) locking scripts."

  require Bitwise
  alias BSV.Script

  @stas3_base_template_hex "6d82736301218763007b7b517c6e5667766b517f786b517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68766c936c7c5493686751687652937a76aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e011f7f7d7e01007e8111414136d08c5ed2bf3ba048afe6dcaebafe01005f80837e01007e7652967b537a7601ff877c0100879b7d648b6752799368537a7d9776547aa06394677768263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01417e7c6421038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b92186721023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc4868ad547f7701207f01207f7701247f517f7801007e02fd00a063546752687f7801007e817f727e7b517f7c01147d887f517f7c01007e817601619f6976014ea063517c7b6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f007b7b687602fd0a7f7701147f7c5579876b826475020100686b587a5893766b7a765155a569005379736382013ca07c517f7c51877b9a6352795487637101007c7e717101207f01147f75777c7567756c766b8b8b79518868677568686c6c7c6b517f7c817f788273638c7f776775010068518463517f7c01147d887f547952876372777c717c767663517f756852875779766352790152879a689b63517f77567a7567527c7681014f0161a5587a9a63015094687e68746c766b5c9388748c76795879888c8c7978886777717c767663517f7568528778015287587a9a9b745394768b797663517f756852877c6c766b5c936ea0637c8c768b797663517f75685287726b9b7c6c686ea0637c5394768b797663517f75685287726b9b7c6c686ea063755494797663517f756852879b676d689b63006968687c717167567a75686d7c518763755279686c755879a9886b6b6b6b6b6b6b827763af686c6c6c6c6c6c6c547a577a7664577a577a587a597a786354807e7e676d68aa880067765158a569765187645294587a53795a7a7e7e78637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6867587a6876aa5a7a7d54807e597a5b7a5c7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa5a7a7d877663516752687c72879b69537a6491687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e817602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75517f7c01147d887f517f7c01007e817601619f6976014ea0637c6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f68557964577988756d67716881687863567a677b68587f7c8153796353795287637b6b537a6b717c6b6b537a6b676b577a6b597a6b587a6b577a6b7c68677b93687c547f7701207f75748c7a7669765880044676a914780114748c7a76727b748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685c795c79636c766b7363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e0a888201218763ac67517f07517f73637c7f6876767e767e7e02ae687e7e7c557a00740111a063005a79646b7c748c7a76697d937b7b58807e6c91677c748c7a7d58807e6c6c6c557a680114748c7a748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685479635f79676c766b0115797363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7c637e677c6b7c6b7c6b7e7c6b68685979636c6c766b786b7363517f7c51876301347f77547f547f75786352797b01007e81957c01007e81965379a169676d68677568685c797363517f7c51876301347f77547f547f75786354797b01007e81957c01007e819678a169676d68677568687568740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68597a636c6c6c6d6c6c6d6c9d687c587a9d7d7e5c79635d795880041976a9145e797e0288ac7e7e6700687d7e5c7a766302006a7c7e827602fc00a06301fd7c7e536751687f757c7e0058807c7e687d7eaa6b7e7e7e7e7e7eaa78877c6c877c6c9a9b726d726d77776a"

  @doc """
  Build a STAS3 locking script.

  ## Parameters
  - `owner_pkh` - 20-byte owner public key hash
  - `redemption_pkh` - 20-byte redemption public key hash
  - `action_data` - optional action data (`{:swap, hash}` or `{:custom, bytes}`)
  - `frozen` - whether the token is frozen
  - `freezable` - whether the token supports freeze operations
  - `service_fields` - list of additional service field binaries
  - `optional_data` - list of additional optional data binaries
  """
  @spec build_stas3_locking_script(
          <<_::160>>,
          <<_::160>>,
          BSV.Tokens.ActionData.t() | nil,
          boolean(),
          boolean() | BSV.Tokens.ScriptFlags.t(),
          [binary()],
          [binary()]
        ) :: {:ok, BSV.Script.t()} | {:error, term()}
  def build_stas3_locking_script(
        <<owner_pkh::binary-size(20)>>,
        <<redemption_pkh::binary-size(20)>>,
        action_data,
        frozen,
        freezable_or_flags,
        service_fields,
        optional_data
      ) do
    {:ok, base_template} = Base.decode16(@stas3_base_template_hex, case: :mixed)

    script = <<>>

    # 1. Push owner PKH (OP_DATA_20 + 20 bytes)
    script = script <> <<0x14>> <> owner_pkh

    # 2. Action data encoding
    script =
      case {frozen, action_data} do
        {false, nil} ->
          script <> <<0x00>>

        {true, nil} ->
          script <> <<0x52>>

        {_, {:swap, %{} = fields}} ->
          script <> push_data(encode_swap_action_data(fields))

        {_, {:custom, bytes}} ->
          script <> push_data(bytes)
      end

    # 3. Base template
    script = script <> base_template

    # 4. OP_RETURN is the last byte of the base template (0x6a)

    # 5. Push redemption PKH
    script = script <> <<0x14>> <> redemption_pkh

    # 6. Flags
    flags = build_stas3_flags(freezable_or_flags)
    script = script <> push_data(flags)

    # 7. Service fields
    script =
      Enum.reduce(service_fields, script, fn field, acc ->
        acc <> push_data(field)
      end)

    # 8. Optional data
    script =
      Enum.reduce(optional_data, script, fn data, acc ->
        acc <> push_data(data)
      end)

    Script.from_binary(script)
  end

  @doc """
  Build flags byte from boolean options.

  Accepts either a single boolean (legacy: freezable only) or a
  `ScriptFlags` struct for full flag support.
  """
  @spec build_stas3_flags(boolean() | BSV.Tokens.ScriptFlags.t()) :: binary()
  def build_stas3_flags(%BSV.Tokens.ScriptFlags{} = flags) do
    BSV.Tokens.ScriptFlags.encode(flags)
  end

  def build_stas3_flags(true), do: <<0x01>>
  def build_stas3_flags(false), do: <<0x00>>

  @doc "Push data with appropriate length prefix."
  @spec push_data(binary()) :: binary()
  def push_data(<<>>), do: <<0x00>>

  def push_data(data) when byte_size(data) <= 75 do
    <<byte_size(data)::8>> <> data
  end

  def push_data(data) when byte_size(data) <= 255 do
    <<0x4C, byte_size(data)::8>> <> data
  end

  def push_data(data) do
    <<0x4D, byte_size(data)::little-16>> <> data
  end

  @doc """
  Encode a STAS 3.0 unlocking-script amount as a minimal little-endian push.

  Per STAS 3.0 v0.1 §7, the `out1_amount`, `out2_amount`, `out3_amount`,
  `out4_amount` and `change_amount` fields are "Unsigned LE (up to 8 B) or
  empty" — i.e. minimal-LE encoded, not fixed 8 bytes. Zero is encoded as the
  empty push.

  Returns the **wire bytes** of the push instruction (length prefix + LE
  payload) suitable for direct concatenation into an unlocking script binary.

  ## Examples

      iex> Stas3Builder.encode_unlock_amount(0)
      <<0x00>>

      iex> Stas3Builder.encode_unlock_amount(1)
      <<0x01, 0x01>>

      iex> Stas3Builder.encode_unlock_amount(0xFF)
      <<0x01, 0xFF>>

      iex> Stas3Builder.encode_unlock_amount(0x100)
      <<0x02, 0x00, 0x01>>
  """
  @spec encode_unlock_amount(non_neg_integer()) :: binary()
  def encode_unlock_amount(0), do: <<0x00>>

  def encode_unlock_amount(amount)
      when is_integer(amount) and amount > 0 and amount <= 0xFFFFFFFFFFFFFFFF do
    push_data(amount_to_minimal_le(amount, <<>>))
  end

  defp amount_to_minimal_le(0, acc), do: acc

  defp amount_to_minimal_le(value, acc) do
    amount_to_minimal_le(Bitwise.bsr(value, 8), acc <> <<Bitwise.band(value, 0xFF)>>)
  end

  @doc """
  Freeze a STAS 3.0 `var2` field (action 0x02) per spec §6.2.

  Takes the **wire bytes** of the original `var2` push (the on-script encoding
  of the var2 push instruction) and returns the wire bytes of the frozen
  marker push.

  Mapping (spec §6.2 table):

    | Original var2 form                          | Frozen var2 form                             |
    | ------------------------------------------- | -------------------------------------------- |
    | empty push (`OP_0`, 0x00)                   | `OP_2` (0x52)                                |
    | pushdata bytelength / OP_PUSHDATA1/2/4 push | prepend `0x02` to the pushed bytes, repush   |
    | `OP_1`, `OP_3`..`OP_16`, `OP_1NEGATE`       | convert to pushdata, then prepend `0x02`     |

  Returns the wire bytes of the new push instruction (a single push opcode +
  payload). `unfreeze_var2/1` is the strict inverse.
  """
  @spec freeze_var2(binary()) :: binary()
  def freeze_var2(<<>>), do: <<0x52>>

  # Empty push (OP_0) → OP_2
  def freeze_var2(<<0x00>>), do: <<0x52>>

  # OP_1 (0x51) — pushes [0x01]
  def freeze_var2(<<0x51>>), do: push_data(<<0x02, 0x01>>)

  # OP_3..OP_16 (0x53..0x60) — push the integer 3..16 as a single byte
  def freeze_var2(<<op>>) when op >= 0x53 and op <= 0x60 do
    push_data(<<0x02, op - 0x50>>)
  end

  # OP_1NEGATE (0x4F) — pushes script-num -1 (single byte 0x81)
  def freeze_var2(<<0x4F>>), do: push_data(<<0x02, 0x81>>)

  # Direct push of 1..75 bytes
  def freeze_var2(<<len, data::binary-size(len)>>) when len >= 0x01 and len <= 0x4B do
    push_data(<<0x02, data::binary>>)
  end

  # OP_PUSHDATA1
  def freeze_var2(<<0x4C, len, data::binary-size(len)>>) do
    push_data(<<0x02, data::binary>>)
  end

  # OP_PUSHDATA2
  def freeze_var2(<<0x4D, len::little-16, data::binary-size(len)>>) do
    push_data(<<0x02, data::binary>>)
  end

  # OP_PUSHDATA4
  def freeze_var2(<<0x4E, len::little-32, data::binary-size(len)>>) do
    push_data(<<0x02, data::binary>>)
  end

  # OP_2 (0x52) — already a pushed-by-opcode 0x02. Treat as pushed-bytes <<0x02>>.
  def freeze_var2(<<0x52>>), do: push_data(<<0x02, 0x02>>)

  @doc """
  Unfreeze a STAS 3.0 `var2` field per spec §6.2.

  Strict inverse of `freeze_var2/1`. Takes the wire bytes of the frozen push
  and returns the wire bytes of the original push.

  Recognised inputs:
    * single byte `OP_2` (0x52) → empty push (`OP_0`, 0x00)
    * any pushdata whose first payload byte is `0x02` → reverse-mapped
      payload (single-byte values 0x01, 0x03..0x10, and 0x81 are remapped
      back to their bare-opcode form; otherwise re-emitted as pushdata)
  """
  @spec unfreeze_var2(binary()) :: binary()
  def unfreeze_var2(<<0x52>>), do: <<0x00>>

  def unfreeze_var2(<<len, 0x02, payload::binary-size(len - 1)>>)
      when len >= 0x01 and len <= 0x4B do
    decode_unfrozen_payload(payload)
  end

  def unfreeze_var2(<<0x4C, len, 0x02, payload::binary-size(len - 1)>>) do
    decode_unfrozen_payload(payload)
  end

  def unfreeze_var2(<<0x4D, len::little-16, 0x02, payload::binary-size(len - 1)>>) do
    decode_unfrozen_payload(payload)
  end

  def unfreeze_var2(<<0x4E, len::little-32, 0x02, payload::binary-size(len - 1)>>) do
    decode_unfrozen_payload(payload)
  end

  # Reverse the bare-opcode → pushdata conversion done by freeze_var2/1.
  # If the original payload was a single byte that an opcode could have pushed,
  # restore that opcode form.
  defp decode_unfrozen_payload(<<0x01>>), do: <<0x51>>

  defp decode_unfrozen_payload(<<v>>) when v >= 0x03 and v <= 0x10 do
    <<0x50 + v>>
  end

  defp decode_unfrozen_payload(<<0x81>>), do: <<0x4F>>

  defp decode_unfrozen_payload(<<0x02>>), do: <<0x52>>

  defp decode_unfrozen_payload(<<>>), do: <<0x00>>

  defp decode_unfrozen_payload(payload), do: push_data(payload)

  @doc """
  Encode swap action data fields into a binary for embedding in a locking script.

  Each swap leg is 61 bytes: 1 (kind 0x01) + 32 (hash) + 20 (pkh) + 4 (numerator LE) + 4 (denominator LE).

  ## Parameters
  - `fields` - Map with `:requested_script_hash` (32 bytes), `:requested_pkh` (20 bytes),
    `:rate_numerator` (uint32), `:rate_denominator` (uint32)

  ## Returns
  A 61-byte binary encoding the swap action data.
  """
  @spec encode_swap_action_data(BSV.Tokens.ActionData.swap_fields()) :: binary()
  def encode_swap_action_data(%{
        requested_script_hash: <<hash::binary-size(32)>>,
        requested_pkh: <<pkh::binary-size(20)>>,
        rate_numerator: num,
        rate_denominator: den
      })
      when is_integer(num) and num >= 0 and num <= 0xFFFFFFFF and
             is_integer(den) and den >= 0 and den <= 0xFFFFFFFF do
    <<0x01, hash::binary, pkh::binary, num::little-32, den::little-32>>
  end

  @doc """
  Decode a swap action data binary into structured fields.

  Parses one or more 61-byte swap legs from the binary. Each leg starts with
  kind byte 0x01 followed by 32-byte hash, 20-byte PKH, and two uint32 LE values.

  ## Parameters
  - `data` - Binary starting with kind byte 0x01

  ## Returns
  `{:ok, swap_fields}` or `{:error, reason}`
  """
  @spec decode_swap_action_data(binary()) ::
          {:ok, BSV.Tokens.ActionData.swap_fields()} | {:error, term()}
  def decode_swap_action_data(
        <<0x01, hash::binary-size(32), pkh::binary-size(20), num::little-32, den::little-32,
          _rest::binary>>
      ) do
    {:ok,
     %{
       requested_script_hash: hash,
       requested_pkh: pkh,
       rate_numerator: num,
       rate_denominator: den
     }}
  end

  def decode_swap_action_data(_), do: {:error, :invalid_swap_action_data}

  @doc """
  Compute the requestedScriptHash for a STAS3 locking script.

  Extracts the "tail" of a locking script (everything after the owner and action_data
  fields), then returns SHA256(tail). This hash is used in swap action data to identify
  the counterparty's expected locking script structure.

  ## Parameters
  - `locking_script` - Full STAS3 locking script binary

  ## Returns
  A 32-byte SHA256 hash of the locking script tail.
  """
  @spec compute_stas3_requested_script_hash(binary()) :: <<_::256>>
  def compute_stas3_requested_script_hash(locking_script) when is_binary(locking_script) do
    tail = extract_stas3_script_tail(locking_script)
    :crypto.hash(:sha256, tail)
  end

  @doc """
  Extract the locking script tail (everything after owner + action_data fields).

  The STAS3 locking script layout is:
  1. Owner field: OP_DATA_20 (0x14) + 20-byte PKH
  2. Action data field: push_data or OP_FALSE(0x00) or OP_2(0x52)
  3. Tail: everything from base template to end of script

  ## Parameters
  - `script` - Full STAS3 locking script binary

  ## Returns
  Binary containing everything after the action_data field.
  """
  @spec extract_stas3_script_tail(binary()) :: binary()
  def extract_stas3_script_tail(<<0x14, _owner::binary-size(20), rest::binary>>) do
    skip_push_data(rest)
  end

  # Skip a single push data item and return the remainder
  defp skip_push_data(<<0x00, rest::binary>>), do: rest
  defp skip_push_data(<<0x52, rest::binary>>), do: rest

  defp skip_push_data(<<len, _data::binary-size(len), rest::binary>>)
       when len >= 0x01 and len <= 0x4B,
       do: rest

  defp skip_push_data(<<0x4C, len, _data::binary-size(len), rest::binary>>), do: rest
  defp skip_push_data(<<0x4D, len::little-16, _data::binary-size(len), rest::binary>>), do: rest
  defp skip_push_data(<<_opcode, rest::binary>>), do: rest
end
