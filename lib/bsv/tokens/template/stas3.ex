defmodule BSV.Tokens.Template.Stas3 do
  @moduledoc """
  STAS3 unlocking script templates (P2PKH and P2MPKH).

  Carries:

    * `signing_key`   — `nil` for no-auth, `{:single, _}` for P2PKH, or
                       `{:multi, keys, multisig}` for P2MPKH (§10.2).
    * `spend_type`    — STAS 3.0 v0.1 §8.2 spendType (1..4).
    * `sighash_flag`  — sighash type byte (defaults to 0x41 = ALL+FORKID).
    * `no_auth`       — when `true`, emit OP_FALSE in place of authz (§10.3).
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
  Create a STAS3 unlocker that emits no signature.

  Per STAS 3.0 v0.1 §9.5 / §10.3, when the input UTXO's `owner` field equals
  `EMPTY_HASH160 = HASH160("")`, the swap engine accepts `OP_FALSE` from that
  side — no signature/pubkey is required (arbitrator-free swap leg).

  Use this template variant for any STAS 3.0 input whose owner is the empty
  hash sentinel. The resulting unlocking script is a single `OP_FALSE` push.
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
    # STAS 3.0 v0.1 §9.5 / §10.3: arbitrator-free swap leg / signature
    # suppression — push OP_FALSE in place of <sig> (and pubkey/redeem
    # buffer) for that input.
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
