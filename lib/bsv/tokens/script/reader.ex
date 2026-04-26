defmodule BSV.Tokens.Script.StasFields do
  @moduledoc "Fields extracted from a STAS v2 locking script."

  @type t :: %__MODULE__{
          owner_hash: <<_::160>>,
          token_id: BSV.Tokens.TokenId.t(),
          redemption_hash: <<_::160>>,
          flags: binary()
        }

  defstruct [:owner_hash, :token_id, :redemption_hash, flags: <<>>]
end

defmodule BSV.Tokens.Script.Stas3Fields do
  @moduledoc """
  Fields extracted from a STAS 3.0 locking script.

  `action_data_parsed` carries the legacy `{:swap, swap_fields()}` /
  `{:custom, bytes}` form (61-byte projection of the swap descriptor,
  no recursive `next`). For the full STAS 3.0 v0.1 §6.3 recursive
  swap descriptor — including any `next` chain — see
  `swap_descriptor`.
  """

  @type t :: %__MODULE__{
          owner: <<_::160>>,
          redemption: <<_::160>>,
          flags: binary(),
          action_data_raw: binary() | nil,
          action_data_parsed: BSV.Tokens.ActionData.t() | nil,
          swap_descriptor: BSV.Tokens.SwapDescriptor.t() | nil,
          service_fields: [binary()],
          optional_data: [binary()],
          frozen: boolean()
        }

  defstruct [
    :owner,
    :redemption,
    flags: <<>>,
    action_data_raw: nil,
    action_data_parsed: nil,
    swap_descriptor: nil,
    service_fields: [],
    optional_data: [],
    frozen: false
  ]
end

defmodule BSV.Tokens.Script.ParsedScript do
  @moduledoc "Result of parsing a locking script."

  @type t :: %__MODULE__{
          script_type: BSV.Tokens.ScriptType.t(),
          stas: BSV.Tokens.Script.StasFields.t() | nil,
          stas3: BSV.Tokens.Script.Stas3Fields.t() | nil
        }

  defstruct [:script_type, stas: nil, stas3: nil]
end

defmodule BSV.Tokens.Script.Reader do
  @moduledoc "Script reader for parsing STAS and STAS 3.0 locking scripts."

  alias BSV.Tokens.TokenId
  alias BSV.Tokens.Script.{ParsedScript, StasFields, Stas3Fields}

  @stas_v2_min_len 1432
  @stas_v2_redemption_offset 1411
  @stas3_base_prefix <<0x6D, 0x82, 0x73, 0x63>>
  @stas3_base_template_len 2812

  @doc "Parse a locking script binary and classify it."
  @spec read_locking_script(binary()) :: ParsedScript.t()
  def read_locking_script(script) when is_binary(script) do
    cond do
      stas_btg?(script) -> parse_stas_btg(script)
      stas_v2?(script) -> parse_stas_v2(script)
      stas3?(script) -> parse_stas3(script)
      p2pkh?(script) -> %ParsedScript{script_type: :p2pkh}
      p2mpkh?(script) -> %ParsedScript{script_type: :p2mpkh}
      op_return?(script) -> %ParsedScript{script_type: :op_return}
      true -> %ParsedScript{script_type: :unknown}
    end
  end

  @doc "Check if a script is a STAS v2 token script."
  @spec is_stas(binary()) :: boolean()
  def is_stas(script), do: stas_v2?(script)

  @doc """
  Check whether a STAS 3.0 locking script's `owner` field equals
  `EMPTY_HASH160 = HASH160("") = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb`.

  Per STAS 3.0 v0.1 §9.5 / §10.3 (signature-suppression / arbitrator-free swap):
  when the owner field on a swap input equals this sentinel, the engine accepts
  `OP_FALSE` for both the signature and pubkey/redeem-buffer slot from that
  side — i.e. that leg is spent without any signing involved.

  Accepts either:
  - the locking-script binary (or `BSV.Script.t()`), or
  - a parsed `Stas3Fields` struct.

  Returns `false` for non-STAS-3.0 scripts.
  """
  @spec arbitrator_free_owner?(
          binary()
          | BSV.Script.t()
          | StasFields.t()
          | Stas3Fields.t()
          | ParsedScript.t()
        ) ::
          boolean()
  def arbitrator_free_owner?(%Stas3Fields{owner: owner}),
    do: owner == BSV.Tokens.Script.Templates.empty_hash160()

  def arbitrator_free_owner?(%ParsedScript{stas3: %Stas3Fields{} = f}),
    do: arbitrator_free_owner?(f)

  def arbitrator_free_owner?(%ParsedScript{}), do: false

  def arbitrator_free_owner?(%BSV.Script{} = script) do
    arbitrator_free_owner?(BSV.Script.to_binary(script))
  end

  def arbitrator_free_owner?(script) when is_binary(script) do
    case read_locking_script(script) do
      %ParsedScript{script_type: :stas3, stas3: %Stas3Fields{} = f} ->
        arbitrator_free_owner?(f)

      _ ->
        false
    end
  end

  def arbitrator_free_owner?(_), do: false

  # STAS-BTG: starts with OP_IF (0x63), contains OP_ELSE/OP_ENDIF, then STAS v2 body (76 a9 14)
  defp stas_btg?(<<0x63, rest::binary>> = script) when byte_size(script) >= 1500 do
    # Look for OP_ENDIF (0x68) followed by STAS v2 body (76 a9 14) in first 400 bytes
    check_btg_structure(rest, byte_size(script))
  end

  defp stas_btg?(_), do: false

  defp check_btg_structure(data, total_len) when total_len >= 1500 do
    # Scan for 0x68 0x76 0xA9 0x14 (OP_ENDIF + STAS v2 P2PKH gate)
    scan_for_endif_stas(data, 0, min(byte_size(data), 400))
  end

  defp check_btg_structure(_, _), do: false

  defp scan_for_endif_stas(_data, offset, max) when offset >= max - 3, do: false

  defp scan_for_endif_stas(data, offset, max) do
    case binary_part(data, offset, 4) do
      <<0x68, 0x76, 0xA9, 0x14>> -> true
      _ -> scan_for_endif_stas(data, offset + 1, max)
    end
  end

  defp parse_stas_btg(script) do
    # Find OP_ENDIF + STAS v2 body offset
    {_preamble_end, body_start} = find_stas_body_offset(script)

    # The STAS v2 body starts at body_start with 76 a9 14
    <<_before::binary-size(body_start), body::binary>> = script
    <<_p2pkh_prefix::binary-size(3), owner_hash::binary-size(20), _rest::binary>> = body

    # Redemption PKH is at offset 1411 within the STAS v2 body
    body_len = byte_size(body)

    {redemption_hash, flags} =
      if body_len >= 1431 do
        <<_::binary-size(1411), rpkh::binary-size(20), flag_data::binary>> = body

        flags =
          case parse_push_data_items(flag_data) do
            [first | _] -> first
            [] -> <<>>
          end

        {rpkh, flags}
      else
        {<<0::160>>, <<>>}
      end

    token_id = TokenId.from_pkh(redemption_hash)

    %ParsedScript{
      script_type: :stas_btg,
      stas: %StasFields{
        owner_hash: owner_hash,
        token_id: token_id,
        redemption_hash: redemption_hash,
        flags: flags
      }
    }
  end

  defp find_stas_body_offset(<<0x63, rest::binary>>) do
    # Scan for 0x68 0x76 0xA9 0x14 pattern
    do_find_body_offset(rest, 1, min(byte_size(rest), 400))
  end

  defp do_find_body_offset(_data, offset, max) when offset >= max - 3 do
    # Fallback — shouldn't happen if stas_btg? passed
    {offset, offset + 1}
  end

  defp do_find_body_offset(data, offset, max) do
    case binary_part(data, offset - 1, 4) do
      <<0x68, 0x76, 0xA9, 0x14>> ->
        # OP_ENDIF at offset, body starts at offset+1 (relative to start of script)
        {offset, offset + 1}

      _ ->
        do_find_body_offset(data, offset + 1, max)
    end
  end

  # STAS v2: prefix 76a914 at start, marker 88ac6976aa60 at byte 23, length >= 1432
  defp stas_v2?(
         <<0x76, 0xA9, 0x14, _owner::binary-size(20), 0x88, 0xAC, 0x69, 0x76, 0xAA, 0x60,
           _rest::binary>> = script
       ) do
    byte_size(script) >= @stas_v2_min_len
  end

  defp stas_v2?(_), do: false

  defp parse_stas_v2(script) do
    <<_prefix::binary-size(3), owner_hash::binary-size(20), _marker::binary-size(6),
      _body::binary-size(@stas_v2_redemption_offset - 29), redemption_hash::binary-size(20),
      op_return_data::binary>> = script

    flags =
      case parse_push_data_items(op_return_data) do
        [first | _] -> first
        [] -> <<>>
      end

    token_id = TokenId.from_pkh(redemption_hash)

    %ParsedScript{
      script_type: :stas,
      stas: %StasFields{
        owner_hash: owner_hash,
        token_id: token_id,
        redemption_hash: redemption_hash,
        flags: flags
      }
    }
  end

  # STAS 3.0: starts with OP_DATA_20 (0x14) + 20 bytes owner
  defp stas3?(<<0x14, _owner::binary-size(20), rest::binary>> = script)
       when byte_size(script) >= 26 do
    case read_push_data(rest) do
      {:ok, _action_data, remaining} ->
        byte_size(remaining) >= 4 and
          binary_part(remaining, 0, 4) == @stas3_base_prefix

      :error ->
        false
    end
  end

  defp stas3?(_), do: false

  defp parse_stas3(<<0x14, owner::binary-size(20), rest::binary>>) do
    {:ok, action_data_raw, after_action} = read_push_data(rest)

    # Skip the base template to find OP_RETURN
    op_return_pos = @stas3_base_template_len - 1

    case after_action do
      <<_template::binary-size(op_return_pos), 0x6A, after_op_return::binary>> ->
        items = parse_push_data_items(after_op_return)

        redemption =
          case items do
            [<<r::binary-size(20)>> | _] -> r
            _ -> <<0::160>>
          end

        flags =
          case items do
            [_, f | _] -> f
            _ -> <<>>
          end

        service_fields =
          case items do
            [_, _ | rest] -> rest
            _ -> []
          end

        frozen = action_data_raw == <<0x52>>

        action_data_parsed =
          case action_data_raw do
            <<0x01, _::binary>> = swap_data ->
              case BSV.Tokens.Script.Stas3Builder.decode_swap_action_data(swap_data) do
                {:ok, fields} -> {:swap, fields}
                _ -> {:custom, swap_data}
              end

            <<0x52>> ->
              nil

            nil ->
              nil

            <<>> ->
              nil

            other ->
              {:custom, other}
          end

        # STAS 3.0 v0.1 §6.3: parse the FULL recursive swap descriptor
        # (including any `next` chain) when the var2 push is a swap
        # action (leading 0x01). Independent of the legacy 61-byte
        # `action_data_parsed` projection above.
        swap_descriptor =
          case action_data_raw do
            <<0x01, _::binary>> = swap_data ->
              case BSV.Tokens.SwapDescriptor.parse(swap_data) do
                {:ok, descriptor} -> descriptor
                _ -> nil
              end

            _ ->
              nil
          end

        %ParsedScript{
          script_type: :stas3,
          stas3: %Stas3Fields{
            owner: owner,
            redemption: redemption,
            flags: flags,
            action_data_raw: action_data_raw,
            action_data_parsed: action_data_parsed,
            swap_descriptor: swap_descriptor,
            service_fields: service_fields,
            optional_data: [],
            frozen: frozen
          }
        }

      _ ->
        %ParsedScript{script_type: :unknown}
    end
  end

  defp p2pkh?(<<0x76, 0xA9, 0x14, _pkh::binary-size(20), 0x88, 0xAC>>),
    do: true

  defp p2pkh?(_), do: false

  # P2MPKH locking script per STAS 3.0 v0.1 §10.2 — fixed 70-byte body:
  #   OP_DUP OP_HASH160 <MPKH:20B> OP_EQUALVERIFY OP_SIZE 0x21 OP_EQUAL
  #   OP_IF OP_CHECKSIG OP_ELSE
  #     OP_1 OP_SPLIT (OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF) x 5
  #     OP_CHECKMULTISIG
  #   OP_ENDIF
  @p2mpkh_lock_suffix <<0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xAC, 0x67, 0x51, 0x7F, 0x51, 0x7F,
                        0x73, 0x63, 0x7C, 0x7F, 0x68, 0x51, 0x7F, 0x73, 0x63, 0x7C, 0x7F, 0x68,
                        0x51, 0x7F, 0x73, 0x63, 0x7C, 0x7F, 0x68, 0x51, 0x7F, 0x73, 0x63, 0x7C,
                        0x7F, 0x68, 0x51, 0x7F, 0x73, 0x63, 0x7C, 0x7F, 0x68, 0xAE, 0x68>>

  defp p2mpkh?(<<0x76, 0xA9, 0x14, _mpkh::binary-size(20), suffix::binary-size(47)>>) do
    suffix == @p2mpkh_lock_suffix
  end

  defp p2mpkh?(_), do: false

  defp op_return?(<<0x6A, _::binary>>), do: true
  defp op_return?(<<0x00, 0x6A, _::binary>>), do: true
  defp op_return?(_), do: false

  # Read a single push data item, returning {:ok, data_or_nil, remaining_binary}
  # or :error on empty input. Handles all Bitcoin pushdata opcodes per STAS 3.0 spec.

  # OP_0 (0x00): empty push
  defp read_push_data(<<0x00, rest::binary>>), do: {:ok, nil, rest}

  # OP_1NEGATE (0x4f): pushes -1, single byte opcode, no following data
  defp read_push_data(<<0x4F, rest::binary>>), do: {:ok, <<0x4F>>, rest}

  # OP_1 through OP_16 (0x51-0x60): push respective values 1-16
  # Single byte opcodes, no following data. Return the opcode byte.
  defp read_push_data(<<opcode, rest::binary>>) when opcode >= 0x51 and opcode <= 0x60 do
    {:ok, <<opcode>>, rest}
  end

  # Direct push: 1-75 bytes (opcode IS the byte length)
  defp read_push_data(<<len, data::binary-size(len), rest::binary>>)
       when len >= 0x01 and len <= 0x4B do
    {:ok, data, rest}
  end

  # OP_PUSHDATA1 (0x4c): 1-byte length prefix
  defp read_push_data(<<0x4C, len, data::binary-size(len), rest::binary>>) do
    {:ok, data, rest}
  end

  # OP_PUSHDATA2 (0x4d): 2-byte LE length prefix
  defp read_push_data(<<0x4D, len::little-16, data::binary-size(len), rest::binary>>) do
    {:ok, data, rest}
  end

  # OP_PUSHDATA4 (0x4e): 4-byte LE length prefix
  defp read_push_data(<<0x4E, len::little-32, data::binary-size(len), rest::binary>>) do
    {:ok, data, rest}
  end

  # Unknown opcode: skip 1 byte, return nil
  defp read_push_data(<<_opcode, rest::binary>>), do: {:ok, nil, rest}

  # Empty input
  defp read_push_data(<<>>), do: :error

  @doc false
  def parse_push_data_items(data), do: do_parse_push_items(data, [])

  # Parses consecutive pushdata items from OP_RETURN data, accumulating results.
  # Handles all Bitcoin pushdata opcodes per STAS 3.0 spec.

  defp do_parse_push_items(<<>>, acc), do: Enum.reverse(acc)

  # OP_0 (0x00): empty push
  defp do_parse_push_items(<<0x00, rest::binary>>, acc),
    do: do_parse_push_items(rest, [<<0x00>> | acc])

  # OP_1NEGATE (0x4f): pushes -1, single byte opcode
  defp do_parse_push_items(<<0x4F, rest::binary>>, acc),
    do: do_parse_push_items(rest, [<<0x4F>> | acc])

  # OP_1 through OP_16 (0x51-0x60): push respective values 1-16
  defp do_parse_push_items(<<opcode, rest::binary>>, acc)
       when opcode >= 0x51 and opcode <= 0x60 do
    do_parse_push_items(rest, [<<opcode>> | acc])
  end

  # Direct push: 1-75 bytes (opcode IS the byte length)
  defp do_parse_push_items(<<len, data::binary-size(len), rest::binary>>, acc)
       when len >= 0x01 and len <= 0x4B do
    do_parse_push_items(rest, [data | acc])
  end

  # OP_PUSHDATA1 (0x4c): 1-byte length prefix
  defp do_parse_push_items(<<0x4C, len, data::binary-size(len), rest::binary>>, acc) do
    do_parse_push_items(rest, [data | acc])
  end

  # OP_PUSHDATA2 (0x4d): 2-byte LE length prefix
  defp do_parse_push_items(<<0x4D, len::little-16, data::binary-size(len), rest::binary>>, acc) do
    do_parse_push_items(rest, [data | acc])
  end

  # OP_PUSHDATA4 (0x4e): 4-byte LE length prefix
  defp do_parse_push_items(<<0x4E, len::little-32, data::binary-size(len), rest::binary>>, acc) do
    do_parse_push_items(rest, [data | acc])
  end

  # Unknown opcode: skip 1 byte, preserve as raw opcode byte
  defp do_parse_push_items(<<opcode, rest::binary>>, acc) do
    do_parse_push_items(rest, [<<opcode>> | acc])
  end
end
