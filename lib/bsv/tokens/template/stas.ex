defmodule BSV.Tokens.Template.Stas do
  @moduledoc """
  STAS unlocking script template.

  Identical to P2PKH: `<sig> <pubkey>`.
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Script, PrivateKey, PublicKey}
  alias BSV.Transaction.Sighash

  defstruct [:private_key, sighash_flag: 0x41]

  @type t :: %__MODULE__{
          private_key: PrivateKey.t(),
          sighash_flag: non_neg_integer()
        }

  @doc "Create a STAS unlocker struct with the given private key."
  @spec unlock(PrivateKey.t(), keyword()) :: t()
  def unlock(%PrivateKey{} = key, opts \\ []) do
    flag = Keyword.get(opts, :sighash_flag, 0x41)
    %__MODULE__{private_key: key, sighash_flag: flag}
  end

  @doc "Sign a STAS input, producing a P2PKH-style unlocking script."
  @impl BSV.Transaction.Template
  def sign(%__MODULE__{private_key: key, sighash_flag: flag}, tx, input_index) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        locking_script_bin = Script.to_binary(source_output.locking_script)
        satoshis = source_output.satoshis

        with {:ok, hash} <-
               Sighash.signature_hash(tx, input_index, locking_script_bin, flag, satoshis),
             {:ok, der_sig} <- PrivateKey.sign(key, hash) do
          sig_with_flag = der_sig <> <<flag::8>>
          pubkey_bytes = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point)
          {:ok, Script.p2pkh_unlock(sig_with_flag, pubkey_bytes)}
        end
    end
  end

  @doc "Estimated unlocking script length in bytes."
  @impl BSV.Transaction.Template
  def estimate_length(_, _, _), do: 106
end
