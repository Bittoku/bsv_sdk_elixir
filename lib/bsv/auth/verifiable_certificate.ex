defmodule BSV.Auth.VerifiableCertificate do
  @moduledoc """
  A certificate with a verifier-specific keyring for selective field decryption.
  """

  alias BSV.Auth.Certificate
  alias BSV.{SymmetricKey}
  alias BSV.Wallet.ProtoWallet
  alias BSV.Wallet.Types.{Counterparty, EncryptionArgs}

  @enforce_keys [:certificate, :keyring]
  defstruct [:certificate, :keyring, decrypted_fields: %{}]

  @type t :: %__MODULE__{
          certificate: Certificate.t(),
          keyring: %{String.t() => String.t()},
          decrypted_fields: %{String.t() => String.t()}
        }

  @doc "Create a new VerifiableCertificate."
  @spec new(Certificate.t(), %{String.t() => String.t()}) :: t()
  def new(%Certificate{} = cert, keyring) do
    %__MODULE__{certificate: cert, keyring: keyring}
  end

  @doc """
  Decrypt the fields using the verifier wallet and the keyring.
  Returns the decrypted fields map and an updated struct.
  """
  @spec decrypt_fields(t(), ProtoWallet.t()) ::
          {:ok, %{String.t() => String.t()}, t()} | {:error, String.t()}
  def decrypt_fields(%__MODULE__{keyring: kr}, _wallet) when map_size(kr) == 0 do
    {:error, "a keyring is required to decrypt certificate fields for the verifier"}
  end

  def decrypt_fields(%__MODULE__{} = vc, %ProtoWallet{} = wallet) do
    subject_cp = %Counterparty{type: :other, public_key: vc.certificate.subject}

    result =
      Enum.reduce_while(vc.keyring, {:ok, %{}}, fn {field_name, encrypted_key_b64}, {:ok, acc} ->
        with {:ok, encrypted_key_bytes} <- Base.decode64(encrypted_key_b64) |> ok_or("invalid base64 keyring"),
             {protocol, key_id} = Certificate.get_encryption_details(field_name, vc.certificate.serial_number),
             enc = %EncryptionArgs{protocol_id: protocol, key_id: key_id, counterparty: subject_cp},
             {:ok, revelation_key} <- ProtoWallet.decrypt(wallet, enc, encrypted_key_bytes),
             {:ok, enc_field_b64} <- Map.fetch(vc.certificate.fields, field_name) |> ok_or("field not found: #{field_name}"),
             {:ok, enc_field_bytes} <- Base.decode64(enc_field_b64) |> ok_or("invalid base64 field value"),
             skey = SymmetricKey.new(revelation_key),
             {:ok, plaintext} <- SymmetricKey.decrypt(skey, enc_field_bytes) do
          {:cont, {:ok, Map.put(acc, field_name, to_string(plaintext))}}
        else
          {:error, reason} -> {:halt, {:error, "field #{field_name}: #{reason}"}}
        end
      end)

    case result do
      {:ok, decrypted} -> {:ok, decrypted, %{vc | decrypted_fields: decrypted}}
      error -> error
    end
  end

  @doc "Verify the certificate signature (delegates to Certificate.verify)."
  @spec verify(t()) :: {:ok, boolean()} | {:error, String.t()}
  def verify(%__MODULE__{certificate: cert}), do: Certificate.verify(cert)

  defp ok_or({:ok, v}, _msg), do: {:ok, v}
  defp ok_or(:error, msg), do: {:error, msg}
end
