defmodule BSV.Contract.PushTxHelpers do
  @moduledoc """
  Helpers for implementing `OP_PUSH_TX` in `BSV.Contract` modules.

  OP_PUSH_TX is a technique enabling true smart contracts on Bitcoin:

  1. Push the BIP-143 transaction preimage into the unlocking script
  2. In the locking script, verify it is the correct preimage using script-level
     signature construction + `OP_CHECKSIG`
  3. Extract any data from the verified preimage for contract logic

  This enables state tracking, spending conditions, and covenants.

  ## Usage

      defmodule MyContract do
        use BSV.Contract
        import BSV.Contract.PushTxHelpers

        def locking_script(ctx, _params) do
          check_tx(ctx)
        end

        def unlocking_script(ctx, _params) do
          push_tx(ctx)
        end
      end
  """

  alias BSV.Contract
  import BSV.Contract.Helpers
  import BSV.Contract.VarIntHelpers

  @order_prefix Base.decode16!("414136D08C5ED2BF3BA048AFE6DCAEBAFE", case: :mixed)
  @pubkey_a Base.decode16!(
              "023635954789A02E39FB7E54440B6F528D53EFD65635DDAD7F3C4085F97FDBDC48",
              case: :mixed
            )
  @pubkey_b Base.decode16!(
              "038FF83D8CF12121491609C4939DC11C4AA35503508FE432DC5A5C1905608B9218",
              case: :mixed
            )
  @pubkey_opt Base.decode16!(
               "02B405D7F0322A89D0F9F3A98E6F938FDC1C969A8D1382A2BF66A71AE74A1E83B0",
               case: :mixed
             )
  @sig_prefix Base.decode16!(
                "3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220",
                case: :mixed
              )
  @sighash_flag 0x41

  @doc "Get the 4-byte tx version from a preimage on top of the stack."
  @spec get_version(Contract.t()) :: Contract.t()
  def get_version(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(0, 4) |> decode_uint()
  end

  @doc "Get the 32-byte prevouts hash from a preimage on top of the stack."
  @spec get_prevouts_hash(Contract.t()) :: Contract.t()
  def get_prevouts_hash(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(4, 32)
  end

  @doc "Get the 32-byte sequence hash from a preimage."
  @spec get_sequence_hash(Contract.t()) :: Contract.t()
  def get_sequence_hash(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(36, 32)
  end

  @doc "Get the 36-byte outpoint (txid + vout) from a preimage."
  @spec get_outpoint(Contract.t()) :: Contract.t()
  def get_outpoint(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(68, 36)
  end

  @doc "Get the locking script from a preimage (with VarInt prefix trimmed)."
  @spec get_script(Contract.t()) :: Contract.t()
  def get_script(%Contract{} = ctx) do
    ctx
    |> op_dup()
    |> trim(104)
    |> trim(-52)
    |> trim_varint()
  end

  @doc "Get the 8-byte input satoshis as a ScriptNum from a preimage."
  @spec get_satoshis(Contract.t()) :: Contract.t()
  def get_satoshis(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(-52, 8) |> decode_uint()
  end

  @doc "Get the 4-byte input sequence number from a preimage."
  @spec get_sequence(Contract.t()) :: Contract.t()
  def get_sequence(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(-44, 4) |> decode_uint()
  end

  @doc "Get the 32-byte outputs hash from a preimage."
  @spec get_outputs_hash(Contract.t()) :: Contract.t()
  def get_outputs_hash(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(-40, 32)
  end

  @doc "Get the 4-byte locktime from a preimage."
  @spec get_lock_time(Contract.t()) :: Contract.t()
  def get_lock_time(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(-8, 4) |> decode_uint()
  end

  @doc "Get the 4-byte sighash type from a preimage."
  @spec get_sighash_type(Contract.t()) :: Contract.t()
  def get_sighash_type(%Contract{} = ctx) do
    ctx |> op_dup() |> slice(-4, 4) |> decode_uint()
  end

  @doc """
  Push the BIP-143 transaction preimage onto the stack.

  When transaction context is available, computes the real preimage.
  Otherwise pushes 181 zero bytes as a placeholder.
  """
  @spec push_tx(Contract.t()) :: Contract.t()
  def push_tx(
        %Contract{
          ctx: {tx, vin},
          subject: %{source_output: source_output}
        } = ctx
      )
      when not is_nil(source_output) do
    locking_script_bin = BSV.Script.to_binary(source_output.locking_script)
    satoshis = source_output.satoshis

    {:ok, preimage} =
      BSV.Transaction.Sighash.calc_preimage(tx, vin, locking_script_bin, @sighash_flag, satoshis)

    push(ctx, preimage)
  end

  def push_tx(%Contract{} = ctx), do: push(ctx, <<0::1448>>)

  @doc """
  Verify the preimage on top of the stack using script-level OP_CHECKSIG.

  Constructs a signature from the sighash in-script and verifies it against
  a known public key. Compiles to ~438 bytes of script.
  """
  @spec check_tx(Contract.t()) :: Contract.t()
  def check_tx(%Contract{} = ctx) do
    ctx
    |> op_hash256()
    |> prepare_sighash()
    |> push_order()
    |> div_order()
    |> sighash_msb_is_0_or_255()
    |> op_if(
      fn c ->
        c
        |> op_2()
        |> op_pick()
        |> op_add()
      end,
      &op_1add/1
    )
    |> sighash_mod_gt_order()
    |> op_if(&op_sub/1, &op_nip/1)
    |> push_sig()
    |> op_swap()
    |> op_if(&push(&1, @pubkey_a), &push(&1, @pubkey_b))
    |> op_checksig()
  end

  @doc "Same as `check_tx/1` but uses OP_CHECKSIGVERIFY."
  @spec check_tx!(Contract.t()) :: Contract.t()
  def check_tx!(%Contract{} = ctx) do
    contract = check_tx(ctx)
    update_in(contract.script.chunks, &List.replace_at(&1, -1, {:op, 0xAD}))
  end

  @doc """
  Optimal OP_PUSH_TX — compiles to ~87 bytes.

  **Warning**: Due to the Low-S constraint, the MSB of the sighash must be < 0x7E.
  There is roughly a 50% chance the signature is invalid per attempt. When using
  this, you must malleate the transaction (e.g. change locktime) until valid.
  """
  @spec check_tx_opt(Contract.t()) :: Contract.t()
  def check_tx_opt(%Contract{} = ctx) do
    ctx
    |> op_hash256()
    |> add_1_to_hash()
    |> push_sig_opt()
    |> push(@pubkey_opt)
    |> op_checksig()
  end

  @doc "Same as `check_tx_opt/1` but uses OP_CHECKSIGVERIFY."
  @spec check_tx_opt!(Contract.t()) :: Contract.t()
  def check_tx_opt!(%Contract{} = ctx) do
    contract = check_tx_opt(ctx)
    update_in(contract.script.chunks, &List.replace_at(&1, -1, {:op, 0xAD}))
  end

  # --- Private helpers ---

  defp prepare_sighash(ctx) do
    ctx
    |> reverse(32)
    |> push(<<0x1F>>)
    |> op_split()
    |> op_tuck()
    |> op_cat()
    |> decode_uint()
  end

  defp push_order(ctx) do
    ctx
    |> push(@order_prefix)
    |> push(<<0>>)
    |> op_15()
    |> op_num2bin()
    |> op_invert()
    |> op_cat()
    |> push(<<0>>)
    |> op_cat()
  end

  defp div_order(ctx) do
    ctx
    |> op_dup()
    |> op_2()
    |> op_div()
  end

  defp sighash_msb_is_0_or_255(ctx) do
    ctx
    |> op_rot()
    |> op_3()
    |> op_roll()
    |> op_dup()
    |> push(<<255>>)
    |> op_equal()
    |> op_swap()
    |> push(<<0>>)
    |> op_equal()
    |> op_boolor()
    |> op_tuck()
  end

  defp sighash_mod_gt_order(ctx) do
    ctx
    |> op_3()
    |> op_roll()
    |> op_tuck()
    |> op_mod()
    |> op_dup()
    |> op_4()
    |> op_roll()
    |> op_greaterthan()
  end

  defp push_sig(ctx) do
    ctx
    |> push(@sig_prefix)
    |> op_swap()
    |> reverse(32)
    |> op_cat()
    |> push(@sighash_flag)
    |> op_cat()
  end

  defp add_1_to_hash(ctx) do
    ctx
    |> op_1()
    |> op_split()
    |> op_swap()
    |> op_bin2num()
    |> op_1add()
    |> op_swap()
    |> op_cat()
  end

  defp push_sig_opt(ctx) do
    ctx
    |> push(@sig_prefix)
    |> op_swap()
    |> op_cat()
    |> push(@sighash_flag)
    |> op_cat()
  end
end
