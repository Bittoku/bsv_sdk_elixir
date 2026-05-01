defmodule BSV.Tokens.Template.Stas3 do
  @moduledoc """
  STAS3 unlocking script templates (P2PKH and P2MPKH).

  Carries:

    * `signing_key`   — `nil` for no-auth, `{:single, _}` for P2PKH, or
                       `{:multi, keys, multisig}` for P2MPKH (§10.2).
    * `spend_type`    — STAS 3.0 v0.1 §8.2 spendType (1..4).
    * `sighash_flag`  — sighash type byte (defaults to 0x41 = ALL+FORKID).
    * `no_auth`       — when `true`, emit OP_FALSE in place of authz (§10.3).
                        The slot-19 sighashPreimage in the §7 witness is
                        UNAFFECTED — see `unlock_no_auth/1` for the spec
                        author's clarification of the word "preimage" in
                        §10.3 (it refers to the address/MPKH preimage in
                        the authz slot 21+, not slot 19).
    * `witness`       — optional `BSV.Tokens.Stas3UnlockWitness.t()` carrying
                        slots 1-20 of the spec §7 witness. When present,
                        `sign/3` prepends the witness bytes to the produced
                        authz script so the resulting unlocking script is
                        `witness ‖ authz`. When absent, the template emits
                        only authz (legacy behaviour, kept for backward
                        compatibility with callers that build the witness
                        themselves or unit-test the authz block in isolation).
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Script, PrivateKey, PublicKey}
  alias BSV.Transaction.{Sighash, P2MPKH}
  alias BSV.Tokens.{SigningKey, Stas3UnlockWitness}

  defstruct [:signing_key, :spend_type, :witness, sighash_flag: 0x41, no_auth: false]

  @type t :: %__MODULE__{
          signing_key: SigningKey.t() | nil,
          spend_type: BSV.Tokens.Stas3SpendType.t(),
          sighash_flag: non_neg_integer(),
          no_auth: boolean(),
          witness: Stas3UnlockWitness.t() | nil
        }

  @doc """
  Create a STAS3 unlocker that emits no signature (spec §9.5 / §10.3).

  When the input UTXO's `owner` field equals `EMPTY_HASH160 = HASH160("")`,
  the swap engine accepts `OP_FALSE` in place of both the signature and the
  **address/MPKH preimage** (the pubkey for P2PKH or the bare-multisig redeem
  buffer for P2MPKH whose `HASH160` equals `owner`). The engine skips all
  ECDSA checks for that party.

  ## Spec author's clarification of the §10.3 word "preimage"

  The "preimage" the spec talks about in §10.3 is the **address/MPKH
  preimage** — the data living in the **authz block (§7 unlock witness slot
  21+)** whose `HASH160` equals the `owner` field. It is NOT the
  **sighashPreimage** (slot 19), which is a BIP-143 transaction preimage
  used by the engine's preimage-driven outputs/sighash checks and which
  MUST remain intact even on the no-auth path.

  Concretely, when this template is paired with `with_witness/2` so the
  produced unlocking script is `witness ‖ authz` (the normal STAS 3.0 v0.1
  §7 shape), the result is:

    * slot 19 (`sighashPreimage`) — the real BIP-143 preimage computed via
      `BSV.Transaction.Sighash.calc_preimage/5`, identical to the P2PKH /
      P2MPKH paths.
    * slot 21+ (`authz`) — a single `OP_FALSE` push (`<<0x00>>`) in place
      of `<sig> <pubkey>` (P2PKH) or `OP_0 <sigs> <redeem>` (P2MPKH).

  Without an attached witness (legacy / unit-test path) the resulting
  unlocking script is just the bare authz region: a single `OP_FALSE`
  push.
  """
  @spec unlock_no_auth(BSV.Tokens.Stas3SpendType.t()) :: t()
  def unlock_no_auth(spend_type) do
    %__MODULE__{
      signing_key: nil,
      spend_type: spend_type,
      sighash_flag: 0x41,
      no_auth: true
    }
  end

  @doc "Create a STAS3 unlocker from a private key (P2PKH, backward compatible)."
  @spec unlock(PrivateKey.t(), BSV.Tokens.Stas3SpendType.t(), keyword()) :: t()
  def unlock(%PrivateKey{} = key, spend_type, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)

    %__MODULE__{
      signing_key: SigningKey.single(key),
      spend_type: spend_type,
      sighash_flag: flag
    }
  end

  @doc "Create a STAS3 P2MPKH unlocker."
  @spec unlock_mpkh(
          [PrivateKey.t()],
          P2MPKH.multisig_script(),
          BSV.Tokens.Stas3SpendType.t(),
          keyword()
        ) ::
          t()
  def unlock_mpkh(private_keys, multisig, spend_type, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)

    %__MODULE__{
      signing_key: SigningKey.multi(private_keys, multisig),
      spend_type: spend_type,
      sighash_flag: flag
    }
  end

  @doc "Create a STAS3 unlocker from a `SigningKey`."
  @spec unlock_from_signing_key(SigningKey.t(), BSV.Tokens.Stas3SpendType.t(), keyword()) :: t()
  def unlock_from_signing_key(signing_key, spend_type, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)

    %__MODULE__{
      signing_key: signing_key,
      spend_type: spend_type,
      sighash_flag: flag
    }
  end

  @doc """
  Attach a `Stas3UnlockWitness` (§7 slots 1-20) to an existing template.

  When the template carries a witness, `sign/3` prepends the encoded
  witness bytes to the produced authz script so the resulting unlocking
  script is `witness ‖ authz` per spec §7.
  """
  @spec with_witness(t(), Stas3UnlockWitness.t()) :: t()
  def with_witness(%__MODULE__{} = tpl, %Stas3UnlockWitness{} = witness) do
    %{tpl | witness: witness}
  end

  @doc "Sign a STAS3 input, producing a P2PKH or P2MPKH unlocking script."
  @impl BSV.Transaction.Template
  def sign(%__MODULE__{no_auth: true} = tpl, _tx, _input_index) do
    # STAS 3.0 v0.1 §9.5 / §10.3 — arbitrator-free swap leg / signature
    # suppression. Per the spec author: the "preimage" the spec talks about
    # in §10.3 is the **address/MPKH preimage** (the pubkey or bare-multisig
    # redeem buffer in authz slot 21+), NOT the BIP-143 sighashPreimage in
    # slot 19. The slot-19 sighashPreimage is supplied by the attached
    # `Stas3UnlockWitness` (computed via `Sighash.calc_preimage/5`) and
    # MUST remain intact even on the no-auth path — the engine still runs
    # preimage-driven outputs/sighash checks for this input.
    #
    # We therefore emit a single OP_FALSE push for the authz region only;
    # the witness prefix produced by `finalize_with_witness/2` already
    # carries the real slot-19 preimage when a witness is attached.
    finalize_with_witness(tpl, %Script{chunks: [{:data, <<>>}]})
  end

  def sign(%__MODULE__{signing_key: sk, sighash_flag: flag} = tpl, tx, input_index) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        locking_script_bin = Script.to_binary(source_output.locking_script)
        satoshis = source_output.satoshis

        with {:ok, hash} <-
               Sighash.signature_hash(tx, input_index, locking_script_bin, flag, satoshis),
             {:ok, authz} <- do_sign(sk, hash, flag) do
          finalize_with_witness(tpl, authz)
        end
    end
  end

  # When the template carries a witness, prepend its bytes (slots 1-20
  # per spec §7) to the authz script. The result is a single Script whose
  # chunks parse back to `witness ‖ authz` byte-for-byte.
  defp finalize_with_witness(%__MODULE__{witness: nil}, %Script{} = authz), do: {:ok, authz}

  defp finalize_with_witness(%__MODULE__{witness: %Stas3UnlockWitness{} = w}, %Script{} = authz) do
    case Stas3UnlockWitness.to_script_bytes(w) do
      {:ok, witness_bytes} ->
        combined_bin = witness_bytes <> Script.to_binary(authz)
        Script.from_binary(combined_bin)

      {:error, _} = err ->
        err
    end
  end

  defp do_sign({:single, key}, hash, flag) do
    with {:ok, der_sig} <- PrivateKey.sign(key, hash) do
      sig_with_flag = der_sig <> <<flag::8>>
      pubkey_bytes = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point)
      {:ok, Script.p2pkh_unlock(sig_with_flag, pubkey_bytes)}
    end
  end

  # P2MPKH unlocking stack per STAS 3.0 v0.1 §10.2 line 414/434:
  #   OP_0 <sig_1> ... <sig_m> <redeem_buffer>
  defp do_sign({:multi, keys, multisig}, hash, flag) do
    case sign_all_keys(keys, hash, flag, []) do
      {:ok, sig_chunks} ->
        ms_bytes = P2MPKH.to_script_bytes(multisig)
        {:ok, %Script{chunks: [{:data, <<>>} | sig_chunks] ++ [{:data, ms_bytes}]}}

      {:error, _} = err ->
        err
    end
  end

  defp sign_all_keys([], _hash, _flag, acc), do: {:ok, Enum.reverse(acc)}

  defp sign_all_keys([key | rest], hash, flag, acc) do
    case PrivateKey.sign(key, hash) do
      {:ok, der_sig} ->
        sig_with_flag = der_sig <> <<flag::8>>
        sign_all_keys(rest, hash, flag, [{:data, sig_with_flag} | acc])

      {:error, _} = err ->
        err
    end
  end

  @doc "Estimated unlocking script length in bytes."
  @impl BSV.Transaction.Template
  def estimate_length(%__MODULE__{no_auth: true}, _, _), do: 1
  def estimate_length(%__MODULE__{signing_key: {:single, _}}, _, _), do: 106

  # OP_0 (1B) + m sigs (m*73) + PUSHDATA1 prefix (2B) + redeem buffer (2 + 34*n)
  def estimate_length(%__MODULE__{signing_key: {:multi, _keys, ms}}, _, _) do
    m = ms.threshold
    n = length(ms.public_keys)
    m * 73 + 34 * n + 5
  end
end
