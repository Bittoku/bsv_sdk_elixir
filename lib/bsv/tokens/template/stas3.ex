defmodule BSV.Tokens.Template.Stas3 do
  @moduledoc """
  STAS3 unlocking script templates (P2PKH and P2MPKH).

  Identical to STAS templates but carries `spend_type` for future preimage encoding.
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Script, PrivateKey, PublicKey}
  alias BSV.Transaction.{Sighash, P2MPKH}
  alias BSV.Tokens.SigningKey

  defstruct [:signing_key, :spend_type, sighash_flag: 0x41]

  @type t :: %__MODULE__{
          signing_key: SigningKey.t(),
          spend_type: BSV.Tokens.Stas3SpendType.t(),
          sighash_flag: non_neg_integer()
        }

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
  @spec unlock_mpkh([PrivateKey.t()], P2MPKH.multisig_script(), BSV.Tokens.Stas3SpendType.t(), keyword()) ::
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

  @doc "Sign a STAS3 input, producing a P2PKH or P2MPKH unlocking script."
  @impl BSV.Transaction.Template
  def sign(%__MODULE__{signing_key: sk, sighash_flag: flag}, tx, input_index) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        locking_script_bin = Script.to_binary(source_output.locking_script)
        satoshis = source_output.satoshis

        with {:ok, hash} <-
               Sighash.signature_hash(tx, input_index, locking_script_bin, flag, satoshis) do
          do_sign(sk, hash, flag)
        end
    end
  end

  defp do_sign({:single, key}, hash, flag) do
    with {:ok, der_sig} <- PrivateKey.sign(key, hash) do
      sig_with_flag = der_sig <> <<flag::8>>
      pubkey_bytes = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point)
      {:ok, Script.p2pkh_unlock(sig_with_flag, pubkey_bytes)}
    end
  end

  defp do_sign({:multi, keys, multisig}, hash, flag) do
    case sign_all_keys(keys, hash, flag, []) do
      {:ok, sig_chunks} ->
        ms_bytes = P2MPKH.to_script_bytes(multisig)
        {:ok, %Script{chunks: sig_chunks ++ [{:data, ms_bytes}]}}

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
  def estimate_length(%__MODULE__{signing_key: {:single, _}}, _, _), do: 106

  def estimate_length(%__MODULE__{signing_key: {:multi, _keys, ms}}, _, _) do
    m = ms.threshold
    n = length(ms.public_keys)
    m * 73 + (3 + n * 34 + 3)
  end
end
