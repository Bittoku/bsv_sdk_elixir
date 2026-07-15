defmodule BSV.Tokens.Script.Stas3Builder do
  @moduledoc "Builder for STAS 3.0 (stas3-freeze-multisig) locking scripts."

  require Bitwise
  alias BSV.Script
  alias BSV.Tokens.Script.Engine

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
        owner_pkh,
        redemption_pkh,
        action_data,
        frozen,
        freezable_or_flags,
        service_fields,
        optional_data
      ) do
    build_stas3_locking_script_with_engine(
      owner_pkh,
      redemption_pkh,
      action_data,
      frozen,
      freezable_or_flags,
      :v0_0_9,
      service_fields,
      optional_data
    )
  end

  @doc """
  Build a STAS 3.0 locking script on an explicit `engine` revision
  (`:v0_0_9` | `:v0_0_11`, see `BSV.Tokens.Script.Engine`).

  Identical to `build_stas3_locking_script/7` but pins the engine body — required
  for NFT / augmentable tokens, which must be built on 0.0.11 (spec §15.6). Pass
  `BSV.Tokens.Script.Engine.select_engine(ScriptFlags.encode(flags))` to choose
  the revision automatically from the flags.
  """
  @spec build_stas3_locking_script_with_engine(
          <<_::160>>,
          <<_::160>>,
          BSV.Tokens.ActionData.t() | nil,
          boolean(),
          boolean() | BSV.Tokens.ScriptFlags.t(),
          Engine.revision(),
          [binary()],
          [binary()]
        ) :: {:ok, BSV.Script.t()} | {:error, term()}
  def build_stas3_locking_script_with_engine(
        <<owner_pkh::binary-size(20)>>,
        <<redemption_pkh::binary-size(20)>>,
        action_data,
        frozen,
        freezable_or_flags,
        engine,
        service_fields,
        optional_data
      ) do
    base_template = Engine.template_bytes(engine)

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

        # STAS 3.0 v0.1 §6.3 recursive swap descriptor: a full
        # SwapDescriptor struct (possibly carrying a `next` chain) is
        # encoded directly via SwapDescriptor.to_var2_bytes/1.
        {_, {:swap, %BSV.Tokens.SwapDescriptor{} = descriptor}} ->
          script <> push_data(BSV.Tokens.SwapDescriptor.to_var2_bytes(descriptor))

        # Legacy 61-byte non-recursive swap_fields() map.
        {_, {:swap, %{} = fields}} ->
          script <> push_data(encode_swap_action_data(fields))

        # Augmentation directive (spec §6.4 / §15.2): action byte 0x03 followed
        # by the data the next spend of an NFT+AUGMENTABLE frame must append.
        {_, {:augment, data}} ->
          script <> push_data(<<0x03>> <> data)

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

  ## Sign-bit safety

  The engine treats the pushed bytes as a Bitcoin script number when it
  later splices them into the BIP-143-style outputs blob via
  `OP_BIN2NUM` / `OP_NUM2BIN`. Bitcoin script numbers are **sign-magnitude
  little-endian**: when the high bit of the most-significant byte is set,
  the value is interpreted as **negative**. For unsigned-LE token amounts
  whose top byte happens to have its high bit set (any value with a top
  byte ≥ 0x80, e.g. 0xBD0E = 48398), we MUST append a `0x00` sentinel
  byte to keep the value non-negative when read as a script number.
  Without it the engine reconstructs a wildly different change amount in
  its outputs blob and the BIP-143 hashOutputs check fails (root cause
  of `:eval_false` for any STAS 3.0 spend whose change amount has a top
  byte ≥ 0x80).

  Returns the **wire bytes** of the push instruction (length prefix + LE
  payload) suitable for direct concatenation into an unlocking script binary.

  ## Examples

      iex> Stas3Builder.encode_unlock_amount(0)
      <<0x00>>

      iex> Stas3Builder.encode_unlock_amount(1)
      <<0x01, 0x01>>

      iex> Stas3Builder.encode_unlock_amount(0x7F)
      <<0x01, 0x7F>>

      # 0xFF requires a sign-bit-disambiguation sentinel.
      iex> Stas3Builder.encode_unlock_amount(0xFF)
      <<0x02, 0xFF, 0x00>>

      iex> Stas3Builder.encode_unlock_amount(0x100)
      <<0x02, 0x00, 0x01>>
  """
  @spec encode_unlock_amount(non_neg_integer()) :: binary()
  def encode_unlock_amount(0), do: <<0x00>>

  def encode_unlock_amount(amount)
      when is_integer(amount) and amount > 0 and amount <= 0xFFFFFFFFFFFFFFFF do
    push_data(amount_to_script_num_le(amount))
  end

  # Encode `amount` as little-endian bytes, appending a `0x00` sign-bit
  # sentinel when the high bit of the most-significant byte is set so the
  # engine reads it back as the same non-negative integer via OP_BIN2NUM.
  defp amount_to_script_num_le(amount) do
    bytes = amount_to_minimal_le(amount, <<>>)
    last = :binary.last(bytes)

    if Bitwise.band(last, 0x80) != 0 do
      bytes <> <<0x00>>
    else
      bytes
    end
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
