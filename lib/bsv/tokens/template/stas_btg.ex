defmodule BSV.Tokens.Template.StasBtg do
  @moduledoc """
  STAS-BTG unlocking script template (Path A — BTG proof).

  Produces unlocking scripts: `<sig> <pubkey> <prefix> <output> <suffix> OP_TRUE`
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Script, PrivateKey, PublicKey}
  alias BSV.Transaction.Sighash
  alias BSV.Tokens.Proof

  defstruct [:private_key, :prev_raw_tx, :prev_vout, sighash_flag: 0x41]

  @type t :: %__MODULE__{
          private_key: PrivateKey.t(),
          prev_raw_tx: binary(),
          prev_vout: non_neg_integer(),
          sighash_flag: non_neg_integer()
        }

  @doc "Create a STAS-BTG Path A (BTG proof) unlocker from a private key and previous raw transaction."
  @spec unlock(PrivateKey.t(), binary(), non_neg_integer(), keyword()) :: t()
  def unlock(%PrivateKey{} = key, prev_raw_tx, prev_vout, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)

    %__MODULE__{
      private_key: key,
      prev_raw_tx: prev_raw_tx,
      prev_vout: prev_vout,
      sighash_flag: flag
    }
  end

  @doc "Sign a STAS-BTG input using Path A (BTG proof), producing `<sig> <pubkey> <prefix> <output> <suffix> OP_TRUE`."
  @impl BSV.Transaction.Template
  def sign(
        %__MODULE__{
          private_key: key,
          sighash_flag: flag,
          prev_raw_tx: prev_raw_tx,
          prev_vout: prev_vout
        },
        tx,
        input_index
      ) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        locking_script_bin = Script.to_binary(source_output.locking_script)
        satoshis = source_output.satoshis

        with {:ok, hash} <- Sighash.signature_hash(tx, input_index, locking_script_bin, flag, satoshis),
             {:ok, der_sig} <- PrivateKey.sign(key, hash),
             {:ok, {prefix, output, suffix}} <- Proof.split_tx_around_output(prev_raw_tx, prev_vout) do
          sig_with_flag = der_sig <> <<flag::8>>
          pubkey_bytes = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point)

          # Build: <sig> <pubkey> <prefix> <output> <suffix> OP_TRUE
          script = %Script{
            chunks: [
              {:data, sig_with_flag},
              {:data, pubkey_bytes},
              {:data, prefix},
              {:data, output},
              {:data, suffix},
              {:op, 0x51}
            ]
          }

          {:ok, script}
        end
    end
  end

  @doc "Estimated unlocking script length including BTG proof data."
  @impl BSV.Transaction.Template
  def estimate_length(%__MODULE__{prev_raw_tx: prev_raw_tx}, _tx, _input_index) do
    # Base sig+pubkey: ~107 bytes
    # Proof data: prev_raw_tx split across three pushes + overhead
    # OP_TRUE: 1 byte
    107 + byte_size(prev_raw_tx) + 10 + 1
  end
end

defmodule BSV.Tokens.Template.StasBtgCheckpoint do
  @moduledoc """
  STAS-BTG checkpoint unlocking script template (Path B — Checkpoint attestation).

  Produces unlocking scripts: `<sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE`
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Script, PrivateKey, PublicKey}
  alias BSV.Transaction.Sighash

  defstruct [:owner_private_key, :issuer_private_key, sighash_flag: 0x41]

  @type t :: %__MODULE__{
          owner_private_key: PrivateKey.t(),
          issuer_private_key: PrivateKey.t(),
          sighash_flag: non_neg_integer()
        }

  @doc "Create a STAS-BTG Path B (checkpoint attestation) unlocker from owner and issuer private keys."
  @spec unlock(PrivateKey.t(), PrivateKey.t(), keyword()) :: t()
  def unlock(%PrivateKey{} = owner_key, %PrivateKey{} = issuer_key, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)

    %__MODULE__{
      owner_private_key: owner_key,
      issuer_private_key: issuer_key,
      sighash_flag: flag
    }
  end

  @doc "Sign a STAS-BTG input using Path B (checkpoint attestation)."
  @impl BSV.Transaction.Template
  def sign(
        %__MODULE__{
          owner_private_key: owner_key,
          issuer_private_key: issuer_key,
          sighash_flag: flag
        },
        tx,
        input_index
      ) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        locking_script_bin = Script.to_binary(source_output.locking_script)
        satoshis = source_output.satoshis

        with {:ok, hash} <- Sighash.signature_hash(tx, input_index, locking_script_bin, flag, satoshis),
             {:ok, owner_der} <- PrivateKey.sign(owner_key, hash),
             {:ok, issuer_der} <- PrivateKey.sign(issuer_key, hash) do
          owner_sig = owner_der <> <<flag::8>>
          issuer_sig = issuer_der <> <<flag::8>>
          owner_pubkey = PrivateKey.to_public_key(owner_key) |> PublicKey.compress() |> Map.get(:point)
          issuer_pubkey = PrivateKey.to_public_key(issuer_key) |> PublicKey.compress() |> Map.get(:point)

          # Build: <sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE
          script = %Script{
            chunks: [
              {:data, owner_sig},
              {:data, owner_pubkey},
              {:data, issuer_sig},
              {:data, issuer_pubkey},
              {:data, <<>>}
            ]
          }

          {:ok, script}
        end
    end
  end

  @doc "Estimated checkpoint unlocking script length in bytes."
  @impl BSV.Transaction.Template
  def estimate_length(_template, _tx, _input_index), do: 217
end
