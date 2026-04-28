defmodule BSV.Tokens.Stas3UnlockWitness do
  @moduledoc """
  STAS 3.0 v0.1 §7 unlocking-script witness assembly (slots 1-20).

  A STAS 3.0 unlock script is built from three concatenated regions:

      witness_bytes       (slots 1-20, this module)
      ‖ authz             (§10 — `<sig> <pubkey>`, OP_0/<sigs>/<redeem>, or
                            OP_FALSE for no-auth) — emitted by
                            `BSV.Tokens.Template.Stas3.sign/3`.
      ‖ trailing_params   (§9.5 atomic-swap counterparty pieces, or
                            §8.1 merge piece array) — emitted by
                            `BSV.Tokens.Script.Stas3Pieces` when txType > 0.

  This module is responsible for the FIRST region only — slots 1 through 20
  pushed in spec order. The structure carries everything required to build
  those bytes; the encoder is `to_script_bytes/1`.

  ## Slot layout (spec §7, in stack-push order)

  | # | Slot               | Type                          | Absence rule                 |
  |---|--------------------|-------------------------------|------------------------------|
  | 1 | out1_amount        | minimal LE up to 8 B          | empty push if no STAS out 1  |
  | 2 | out1_addr          | 20 B owner PKH                | empty push                   |
  | 3 | out1_var2          | single push                   | (always pushed; can be empty)|
  | 4-6 | out2_*           | same as out1 triplet          | SKIPPED entirely if absent   |
  | 7-9 | out3_*           | same as out1 triplet          | SKIPPED entirely if absent   |
  | 10-12 | out4_*         | same as out1 triplet          | SKIPPED entirely if absent   |
  | 13 | change_amount     | minimal LE                    | OP_FALSE (`<<0x00>>`)        |
  | 14 | change_addr       | 20 B raw P2PKH-PKH            | OP_FALSE                     |
  | 15 | noteData          | payload (max 65 533 B)        | OP_FALSE                     |
  | 16 | fundIdx           | 4 B LE uint32                 | OP_FALSE                     |
  | 17 | fundTxid          | 32 B raw                      | OP_FALSE                     |
  | 18 | txType            | 1 B (0..7)                    | always present               |
  | 19 | sighashPreimage   | variable                      | always present               |
  | 20 | spendType         | 1 B (1..4)                    | always present               |

  Slots 4-6, 7-9, 10-12 are SKIPPED entirely (no opcode at all) when the
  matching STAS output is not produced. Slots 13-17 always emit a single
  push: either the value or OP_FALSE per the absence column above.

  This split between "skip vs OP_FALSE" mirrors the spec verbatim
  (§7 footnotes *) and **).
  """

  alias BSV.Tokens.{SpendType, TxType}
  alias BSV.Tokens.Script.Stas3Builder

  @max_note_bytes 65_533

  @typedoc """
  A single STAS output triplet for the witness (slots 1-3, 4-6, 7-9, 10-12).
  """
  @type stas_output :: %{
          required(:amount) => non_neg_integer(),
          required(:owner_pkh) => <<_::160>>,
          required(:var2) => binary()
        }

  @typedoc "A change output (P2PKH satoshi remainder)."
  @type change :: %{
          required(:amount) => non_neg_integer(),
          required(:addr_pkh) => <<_::160>>
        }

  @typedoc "Funding-input identification."
  @type funding_input :: %{
          required(:txid) => <<_::256>>,
          required(:vout) => non_neg_integer()
        }

  @type t :: %__MODULE__{
          stas_outputs: [stas_output()],
          change: change() | nil,
          note_data: binary() | nil,
          funding_input: funding_input() | nil,
          tx_type: TxType.t() | non_neg_integer(),
          sighash_preimage: binary(),
          spend_type: SpendType.t()
        }

  defstruct stas_outputs: [],
            change: nil,
            note_data: nil,
            funding_input: nil,
            tx_type: :regular,
            sighash_preimage: <<>>,
            spend_type: :transfer

  @doc """
  Encode a `Stas3UnlockWitness` to its raw witness-script bytes (slots 1-20)
  per spec §7.

  Returns `{:ok, bytes}` on success or `{:error, reason}` on validation
  failure:

    * `{:error, :note_data_too_large}` — note payload exceeds 65 533 B.
    * `{:error, {:too_many_stas_outputs, n}}` — more than 4 STAS outputs.
    * `{:error, :invalid_sighash_preimage}` — preimage is not a binary.

  The output of this function is meant to be concatenated with the authz
  bytes (and any txType-trailing piece-array bytes) to form the complete
  unlocking script.
  """
  @spec to_script_bytes(t()) :: {:ok, binary()} | {:error, term()}
  def to_script_bytes(%__MODULE__{} = w) do
    cond do
      not is_binary(w.sighash_preimage) ->
        {:error, :invalid_sighash_preimage}

      length(w.stas_outputs) > 4 ->
        {:error, {:too_many_stas_outputs, length(w.stas_outputs)}}

      w.note_data != nil and byte_size(w.note_data) > @max_note_bytes ->
        {:error, :note_data_too_large}

      true ->
        {:ok, do_encode(w)}
    end
  end

  # ── encoder internals ───────────────────────────────────────────────────

  defp do_encode(%__MODULE__{} = w) do
    encode_stas_outputs(w.stas_outputs) <>
      encode_change(w.change) <>
      encode_note(w.note_data) <>
      encode_funding(w.funding_input) <>
      encode_tx_type(w.tx_type) <>
      encode_preimage(w.sighash_preimage) <>
      encode_spend_type(w.spend_type)
  end

  # Slots 1-12: 1..4 triplets. Outputs 2-4 are skipped entirely (no push)
  # when absent. Output 1 is mandatory in the spec but we honour an
  # empty `stas_outputs` list by pushing two empty pushes (out1_amount,
  # out1_addr) and an empty var2 — useful for builders that need a
  # placeholder while wiring code paths. In practice spec §9 always
  # requires at least one STAS output for spendType ∈ {1, 2, 4}.
  defp encode_stas_outputs([]) do
    Stas3Builder.encode_unlock_amount(0) <>
      Stas3Builder.push_data(<<>>) <>
      Stas3Builder.push_data(<<>>)
  end

  defp encode_stas_outputs(outs) when is_list(outs) do
    Enum.map_join(outs, <<>>, &encode_one_stas_output/1)
  end

  defp encode_one_stas_output(%{amount: amt, owner_pkh: <<pkh::binary-size(20)>>, var2: var2})
       when is_integer(amt) and amt >= 0 and is_binary(var2) do
    Stas3Builder.encode_unlock_amount(amt) <>
      Stas3Builder.push_data(pkh) <>
      Stas3Builder.push_data(var2)
  end

  # Slot 13-14: change. OP_FALSE for both when nil; otherwise minimal-LE
  # amount + 20-byte addr push.
  defp encode_change(nil), do: <<0x00>> <> <<0x00>>

  defp encode_change(%{amount: amt, addr_pkh: <<pkh::binary-size(20)>>})
       when is_integer(amt) and amt >= 0 do
    Stas3Builder.encode_unlock_amount(amt) <> Stas3Builder.push_data(pkh)
  end

  # Slot 15: noteData. OP_FALSE when nil, otherwise a single push of the
  # payload bytes.
  defp encode_note(nil), do: <<0x00>>
  defp encode_note(<<>>), do: <<0x00>>
  defp encode_note(bytes) when is_binary(bytes), do: Stas3Builder.push_data(bytes)

  # Slots 16-17: funding input identification. OP_FALSE when nil, else
  # 4-byte LE vout push followed by 32-byte txid push.
  defp encode_funding(nil), do: <<0x00>> <> <<0x00>>

  defp encode_funding(%{txid: <<txid::binary-size(32)>>, vout: vout})
       when is_integer(vout) and vout >= 0 and vout <= 0xFFFFFFFF do
    Stas3Builder.push_data(<<vout::little-32>>) <> Stas3Builder.push_data(txid)
  end

  # Slot 18: txType (always 1-byte push).
  defp encode_tx_type(byte) when is_integer(byte) and byte >= 0 and byte <= 7 do
    Stas3Builder.push_data(<<byte>>)
  end

  defp encode_tx_type(atom) when is_atom(atom) do
    Stas3Builder.push_data(<<TxType.to_byte(atom)>>)
  end

  # Slot 19: BIP-143-style sighash preimage. Always pushed (variable).
  defp encode_preimage(<<>>), do: <<0x00>>
  defp encode_preimage(bytes) when is_binary(bytes), do: Stas3Builder.push_data(bytes)

  # Slot 20: spendType (always 1-byte push).
  defp encode_spend_type(byte) when is_integer(byte) and byte >= 1 and byte <= 4 do
    Stas3Builder.push_data(<<byte>>)
  end

  defp encode_spend_type(atom) when is_atom(atom) do
    Stas3Builder.push_data(<<SpendType.to_byte(atom)>>)
  end

  @doc "Maximum permitted note-data payload length (spec §11)."
  @spec max_note_bytes() :: pos_integer()
  def max_note_bytes, do: @max_note_bytes
end
