defmodule BSV.Auth.Certificate do
  @moduledoc """
  BRC-31 identity certificate.

  A certificate binds a subject's public key to a set of encrypted fields,
  signed by a certifier. Fields are encrypted with per-field symmetric keys.

  Binary format:
  `type (32 bytes) || serial (32 bytes) || subject (33 bytes) || certifier (33 bytes) ||
   revocation_outpoint (36 bytes) || field_count (varint) || fields... || [sig_len (varint) || signature]`
  """

  alias BSV.{PublicKey, VarInt}
  alias BSV.Wallet.ProtoWallet
  alias BSV.Wallet.Types.{Protocol, Counterparty, EncryptionArgs}

  @enforce_keys [:cert_type, :serial_number, :subject, :certifier]
  defstruct [
    :cert_type,
    :serial_number,
    :subject,
    :certifier,
    revocation_outpoint: String.duplicate("0", 64) <> ".0",
    fields: %{},
    signature: <<>>
  ]

  @type t :: %__MODULE__{
          cert_type: String.t(),
          serial_number: String.t(),
          subject: PublicKey.t(),
          certifier: PublicKey.t(),
          revocation_outpoint: String.t(),
          fields: %{String.t() => String.t()},
          signature: binary()
        }

  @doc "Serialize the certificate to binary format."
  @spec to_binary(t(), boolean()) :: {:ok, binary()} | {:error, String.t()}
  def to_binary(%__MODULE__{} = cert, include_signature \\ true) do
    with {:ok, type_bytes} <- Base.decode64(cert.cert_type),
         {:ok, serial_bytes} <- Base.decode64(cert.serial_number),
         {:ok, outpoint_bytes} <- encode_outpoint(cert.revocation_outpoint) do
      sorted_fields = cert.fields |> Enum.sort_by(fn {k, _} -> k end)

      fields_bin =
        Enum.reduce(sorted_fields, <<>>, fn {name, value}, acc ->
          name_bytes = name
          value_bytes = value
          acc <>
            VarInt.encode(byte_size(name_bytes)) <> name_bytes <>
            VarInt.encode(byte_size(value_bytes)) <> value_bytes
        end)

      sig_bin =
        if include_signature and byte_size(cert.signature) > 0 do
          VarInt.encode(byte_size(cert.signature)) <> cert.signature
        else
          <<>>
        end

      {:ok,
       type_bytes <>
         serial_bytes <>
         cert.subject.point <>
         cert.certifier.point <>
         outpoint_bytes <>
         VarInt.encode(map_size(cert.fields)) <>
         fields_bin <>
         sig_bin}
    else
      :error -> {:error, "invalid base64 in cert_type or serial_number"}
      err -> err
    end
  end

  @doc "Deserialize a certificate from binary format."
  @spec from_binary(binary()) :: {:ok, t()} | {:error, String.t()}
  def from_binary(<<
        type_bytes::binary-size(32),
        serial_bytes::binary-size(32),
        subject_bytes::binary-size(33),
        certifier_bytes::binary-size(33),
        outpoint_bytes::binary-size(36),
        rest::binary
      >>) do
    with {:ok, subject} <- PublicKey.from_bytes(subject_bytes),
         {:ok, certifier} <- PublicKey.from_bytes(certifier_bytes) do
      cert_type = Base.encode64(type_bytes)
      serial_number = Base.encode64(serial_bytes)
      revocation_outpoint = decode_outpoint(outpoint_bytes)

      {fields, rest2} = read_fields(rest)

      signature =
        if byte_size(rest2) > 0 do
          {:ok, {sig_len, rest3}} = VarInt.decode(rest2)
          <<sig::binary-size(sig_len), _::binary>> = rest3
          sig
        else
          <<>>
        end

      {:ok,
       %__MODULE__{
         cert_type: cert_type,
         serial_number: serial_number,
         subject: subject,
         certifier: certifier,
         revocation_outpoint: revocation_outpoint,
         fields: fields,
         signature: signature
       }}
    end
  end

  def from_binary(_), do: {:error, "certificate binary too short"}

  @doc """
  Sign the certificate using the certifier's wallet (ProtoWallet).
  Returns a new certificate with the signature set.
  """
  @spec sign(t(), ProtoWallet.t()) :: {:ok, t()} | {:error, String.t()}
  def sign(%__MODULE__{signature: sig} = _cert, _wallet) when byte_size(sig) > 0 do
    {:error, "certificate already signed"}
  end

  def sign(%__MODULE__{} = cert, %ProtoWallet{} = wallet) do
    # Update certifier to wallet's identity key
    certifier_pub = ProtoWallet.identity_key(wallet)
    cert = %{cert | certifier: certifier_pub}

    with {:ok, data} <- to_binary(cert, false) do
      enc = %EncryptionArgs{
        protocol_id: %Protocol{security_level: 2, protocol: "certificate signature"},
        key_id: "#{cert.cert_type} #{cert.serial_number}",
        counterparty: %Counterparty{type: :anyone}
      }

      case ProtoWallet.create_signature(wallet, enc, data, nil) do
        {:ok, sig_der} -> {:ok, %{cert | signature: sig_der}}
        error -> error
      end
    end
  end

  @doc """
  Verify the certificate signature.
  """
  @spec verify(t()) :: {:ok, boolean()} | {:error, String.t()}
  def verify(%__MODULE__{signature: <<>>}), do: {:error, "certificate not signed"}

  def verify(%__MODULE__{} = cert) do
    # Use an anyone wallet for verification
    anyone = ProtoWallet.anyone()

    with {:ok, data} <- to_binary(cert, false) do
      enc = %EncryptionArgs{
        protocol_id: %Protocol{security_level: 2, protocol: "certificate signature"},
        key_id: "#{cert.cert_type} #{cert.serial_number}",
        counterparty: %Counterparty{type: :other, public_key: cert.certifier}
      }

      ProtoWallet.verify_signature(anyone, enc, data, nil, cert.signature, for_self: false)
    end
  end

  @doc "Get the encryption protocol and key ID for a certificate field."
  @spec get_encryption_details(String.t(), String.t()) :: {Protocol.t(), String.t()}
  def get_encryption_details(field_name, serial_number) do
    protocol = %Protocol{
      security_level: 2,
      protocol: "certificate field encryption"
    }

    key_id =
      if serial_number != "" do
        "#{serial_number} #{field_name}"
      else
        field_name
      end

    {protocol, key_id}
  end

  # --- Private ---

  defp read_fields(data) do
    {:ok, {count, rest}} = VarInt.decode(data)
    read_n_fields(rest, count, %{})
  end

  defp read_n_fields(rest, 0, acc), do: {acc, rest}

  defp read_n_fields(data, n, acc) do
    {:ok, {name_len, rest}} = VarInt.decode(data)
    <<name::binary-size(name_len), rest2::binary>> = rest
    {:ok, {value_len, rest3}} = VarInt.decode(rest2)
    <<value::binary-size(value_len), rest4::binary>> = rest3
    read_n_fields(rest4, n - 1, Map.put(acc, name, value))
  end

  defp encode_outpoint(""), do: {:ok, <<0::288>>}

  defp encode_outpoint(outpoint) do
    case String.split(outpoint, ".") do
      [txid_hex, index_str] ->
        with {index, ""} <- Integer.parse(index_str),
             {:ok, txid_bytes} <- Base.decode16(txid_hex, case: :mixed) do
          if byte_size(txid_bytes) == 32 do
            {:ok, txid_bytes <> <<index::little-32>>}
          else
            {:error, "txid must be 32 bytes"}
          end
        else
          _ -> {:error, "invalid outpoint format: #{outpoint}"}
        end

      _ ->
        {:error, "invalid outpoint format: #{outpoint}"}
    end
  end

  defp decode_outpoint(<<txid::binary-size(32), index::little-32>>) do
    txid_hex = Base.encode16(txid, case: :lower)
    "#{txid_hex}.#{index}"
  end
end
