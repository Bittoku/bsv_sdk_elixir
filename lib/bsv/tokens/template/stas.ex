defmodule BSV.Tokens.Template.Stas do
  @moduledoc """
  STAS unlocking script templates (P2PKH and P2MPKH).

  Supports both legacy (P2PKH-only, no spend type) and v3 (with spend type)
  signing modes.

  For P2PKH: produces `<sig> <pubkey>`.
  For P2MPKH: produces `<sig1> … <sigM> <serialized_multisig_script>`.

  The on-chain STAS script auto-detects the format based on the size of the
  public key data: 33 bytes → P2PKH; otherwise → P2MPKH.
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Script, PrivateKey, PublicKey}
  alias BSV.Transaction.{Sighash, P2MPKH}
  alias BSV.Tokens.SigningKey

  defstruct [:signing_key, :spend_type, sighash_flag: 0x41]

  @type t :: %__MODULE__{
          signing_key: SigningKey.t(),
          spend_type: BSV.Tokens.SpendType.t() | nil,
          sighash_flag: non_neg_integer()
        }

  @doc """
  Create a STAS unlocker struct from a `PrivateKey` (P2PKH, backward compatible).

  ## Options
  - `:spend_type` — `SpendType.t()` for v3 scripts (default: `nil` for legacy)
  - `:sighash_flag` — sighash flag byte (default: `0x41`)
  """
  @spec unlock(PrivateKey.t(), keyword()) :: t()
  def unlock(%PrivateKey{} = key, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)
    spend_type = Keyword.get(opts, :spend_type, nil)

    %__MODULE__{
      signing_key: SigningKey.single(key),
      spend_type: spend_type,
      sighash_flag: flag
    }
  end

  @doc """
  Create a STAS P2MPKH unlocker struct from threshold keys and a multisig script.

  ## Options
  - `:spend_type` — `SpendType.t()` for v3 scripts (default: `nil`)
  - `:sighash_flag` — sighash flag byte (default: `0x41`)
  """
  @spec unlock_mpkh([PrivateKey.t()], P2MPKH.multisig_script(), keyword()) :: t()
  def unlock_mpkh(private_keys, multisig, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)
    spend_type = Keyword.get(opts, :spend_type, nil)

    %__MODULE__{
      signing_key: SigningKey.multi(private_keys, multisig),
      spend_type: spend_type,
      sighash_flag: flag
    }
  end

  @doc """
  Create a STAS unlocker from a `SigningKey` (dispatches P2PKH vs P2MPKH).
  """
  @spec unlock_from_signing_key(SigningKey.t(), keyword()) :: t()
  def unlock_from_signing_key(signing_key, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)
    spend_type = Keyword.get(opts, :spend_type, nil)

    %__MODULE__{
      signing_key: signing_key,
      spend_type: spend_type,
      sighash_flag: flag
    }
  end

  @doc "Sign a STAS input, producing a P2PKH or P2MPKH unlocking script."
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

  # P2PKH signing: <sig> <pubkey>
  defp do_sign({:single, key}, hash, flag) do
    with {:ok, der_sig} <- PrivateKey.sign(key, hash) do
      sig_with_flag = der_sig <> <<flag::8>>
      pubkey_bytes = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point)
      {:ok, Script.p2pkh_unlock(sig_with_flag, pubkey_bytes)}
    end
  end

  # P2MPKH signing: <sig1> … <sigM> <multisig_script>
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
