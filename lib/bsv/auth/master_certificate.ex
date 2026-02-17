defmodule BSV.Auth.MasterCertificate do
  @moduledoc """
  A master certificate with encrypted symmetric keys for each field.

  The master keyring maps field names to base64-encoded encrypted symmetric keys.
  These keys can decrypt the corresponding certificate fields, and can be
  re-encrypted for specific verifiers.
  """

  alias BSV.Auth.Certificate
  alias BSV.{SymmetricKey}
  alias BSV.Wallet.ProtoWallet
  alias BSV.Wallet.Types.{Counterparty, EncryptionArgs}

  @enforce_keys [:certificate, :master_keyring]
  defstruct [:certificate, :master_keyring]

  @type t :: %__MODULE__{
          certificate: Certificate.t(),
          master_keyring: %{String.t() => String.t()}
        }

  @doc "Create a new MasterCertificate, validating the keyring covers all fields."
  @spec new(Certificate.t(), %{String.t() => String.t()}) :: {:ok, t()} | {:error, String.t()}
  def new(%Certificate{} = _cert, master_keyring) when map_size(master_keyring) == 0 do
    {:error, "missing master keyring"}
  end

  def new(%Certificate{} = cert, master_keyring) do
    missing = Map.keys(cert.fields) -- Map.keys(master_keyring)

    if missing != [] do
      {:error, "master keyring must contain a value for every field. Missing key for field: #{hd(missing)}"}
    else
      {:ok, %__MODULE__{certificate: cert, master_keyring: master_keyring}}
    end
  end

  @doc """
  Encrypt certificate fields and generate a master keyring.

  Takes a wallet, counterparty (certifier or subject), and plaintext fields.
  Returns `{encrypted_fields, master_keyring}`.
  """
  @spec create_certificate_fields(ProtoWallet.t(), Counterparty.t(), %{String.t() => String.t()}) ::
          {:ok, %{String.t() => String.t()}, %{String.t() => String.t()}} | {:error, String.t()}
  def create_certificate_fields(%ProtoWallet{} = wallet, %Counterparty{} = counterparty, fields) do
    Enum.reduce_while(fields, {:ok, %{}, %{}}, fn {field_name, field_value}, {:ok, enc_fields, keyring} ->
      # Generate random 32-byte symmetric key
      key_bytes = :crypto.strong_rand_bytes(32)
      skey = SymmetricKey.new(key_bytes)

      # Encrypt field value with symmetric key
      {:ok, encrypted_value} = SymmetricKey.encrypt(skey, field_value)
      enc_value_b64 = Base.encode64(encrypted_value)

      # Encrypt symmetric key for counterparty
      {protocol, key_id} = Certificate.get_encryption_details(field_name, "")
      enc = %EncryptionArgs{
        protocol_id: protocol,
        key_id: key_id,
        counterparty: counterparty
      }

      case ProtoWallet.encrypt(wallet, enc, key_bytes) do
        {:ok, encrypted_key} ->
          enc_key_b64 = Base.encode64(encrypted_key)
          {:cont, {:ok, Map.put(enc_fields, field_name, enc_value_b64), Map.put(keyring, field_name, enc_key_b64)}}

        {:error, reason} ->
          {:halt, {:error, "encrypt field #{field_name}: #{reason}"}}
      end
    end)
  end

  @doc """
  Decrypt a single field using the master keyring.

  Returns `{field_revelation_key, plaintext_value}`.
  """
  @spec decrypt_field(ProtoWallet.t(), %{String.t() => String.t()}, String.t(), String.t(), Counterparty.t()) ::
          {:ok, binary(), String.t()} | {:error, String.t()}
  def decrypt_field(%ProtoWallet{} = wallet, master_keyring, field_name, encrypted_field_value, %Counterparty{} = counterparty) do
    with {:ok, encrypted_key_b64} <- Map.fetch(master_keyring, field_name) |> ok_or("key not found in keyring: #{field_name}"),
         {:ok, encrypted_key_bytes} <- Base.decode64(encrypted_key_b64) |> ok_or("invalid base64 in keyring for #{field_name}") do
      {protocol, key_id} = Certificate.get_encryption_details(field_name, "")
      enc = %EncryptionArgs{protocol_id: protocol, key_id: key_id, counterparty: counterparty}

      with {:ok, field_revelation_key} <- ProtoWallet.decrypt(wallet, enc, encrypted_key_bytes),
           {:ok, encrypted_field_bytes} <- Base.decode64(encrypted_field_value) |> ok_or("invalid base64 field value"),
           skey = SymmetricKey.new(field_revelation_key),
           {:ok, plaintext} <- SymmetricKey.decrypt(skey, encrypted_field_bytes) do
        {:ok, field_revelation_key, to_string(plaintext)}
      end
    end
  end

  @doc "Decrypt all fields using the master keyring."
  @spec decrypt_fields(ProtoWallet.t(), %{String.t() => String.t()}, %{String.t() => String.t()}, Counterparty.t()) ::
          {:ok, %{String.t() => String.t()}} | {:error, String.t()}
  def decrypt_fields(%ProtoWallet{} = wallet, master_keyring, fields, %Counterparty{} = counterparty) do
    Enum.reduce_while(fields, {:ok, %{}}, fn {name, encrypted_value}, {:ok, acc} ->
      case decrypt_field(wallet, master_keyring, name, encrypted_value, counterparty) do
        {:ok, _key, plaintext} -> {:cont, {:ok, Map.put(acc, name, plaintext)}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  @doc """
  Create a keyring for a verifier to decrypt specific fields.

  Re-encrypts the field revelation keys for the verifier.
  """
  @spec create_keyring_for_verifier(
          ProtoWallet.t(),
          Counterparty.t(),
          Counterparty.t(),
          %{String.t() => String.t()},
          [String.t()],
          %{String.t() => String.t()},
          String.t()
        ) :: {:ok, %{String.t() => String.t()}} | {:error, String.t()}
  def create_keyring_for_verifier(wallet, certifier, verifier, fields, fields_to_reveal, master_keyring, serial_number) do
    Enum.reduce_while(fields_to_reveal, {:ok, %{}}, fn field_name, {:ok, acc} ->
      enc_value = Map.get(fields, field_name)

      if enc_value == nil do
        {:halt, {:error, "field not found: #{field_name}"}}
      else
        case decrypt_field(wallet, master_keyring, field_name, enc_value, certifier) do
          {:ok, revelation_key, _plaintext} ->
            {protocol, key_id} = Certificate.get_encryption_details(field_name, serial_number)
            enc = %EncryptionArgs{protocol_id: protocol, key_id: key_id, counterparty: verifier}

            case ProtoWallet.encrypt(wallet, enc, revelation_key) do
              {:ok, encrypted} ->
                {:cont, {:ok, Map.put(acc, field_name, Base.encode64(encrypted))}}
              {:error, reason} ->
                {:halt, {:error, "encrypt for verifier: #{reason}"}}
            end

          {:error, reason} ->
            {:halt, {:error, reason}}
        end
      end
    end)
  end

  defp ok_or({:ok, v}, _msg), do: {:ok, v}
  defp ok_or(:error, msg), do: {:error, msg}
end
