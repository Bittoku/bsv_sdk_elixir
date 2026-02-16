defmodule BSV.Message.Signed do
  @moduledoc """
  BRC-77 message signing and verification.

  Wire format:
  `version (4 bytes) || sender_pubkey (33 bytes) || verifier (1 or 33 bytes) || key_id (32 bytes) || signature_der`

  For "anyone" verification, verifier is a single `0x00` byte.
  For specific-recipient verification, verifier is the 33-byte compressed public key.

  See: <https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0077.md>
  """

  alias BSV.{PrivateKey, PublicKey, Crypto}

  @version <<0x42, 0x42, 0x33, 0x01>>
  @anyone_key_bytes <<0::248, 1::8>>

  @doc """
  Sign a message. If `verifier` is `nil`, anyone can verify the signature.
  """
  @spec sign(binary(), PrivateKey.t(), PublicKey.t() | nil) :: {:ok, binary()} | {:error, String.t()}
  def sign(message, %PrivateKey{} = signer, verifier \\ nil) do
    {verifier_pub, anyone?} = resolve_verifier(verifier)

    key_id = :crypto.strong_rand_bytes(32)
    key_id_b64 = Base.encode64(key_id)
    invoice_number = "2-message signing-#{key_id_b64}"

    with {:ok, signing_priv} <- PrivateKey.derive_child(signer, verifier_pub, invoice_number) do
      hashed = Crypto.sha256(message)
      {:ok, signature_der} = PrivateKey.sign(signing_priv, hashed)

      sender_pub = PrivateKey.to_public_key(signer).point
      verifier_bytes = if anyone?, do: <<0x00>>, else: verifier_pub.point

      {:ok, @version <> sender_pub <> verifier_bytes <> key_id <> signature_der}
    end
  end

  @doc """
  Verify a signed message. For "anyone" signatures, pass `nil` as recipient.
  For specific-recipient signatures, pass the recipient's private key.
  """
  @spec verify(binary(), binary(), PrivateKey.t() | nil) :: {:ok, boolean()} | {:error, String.t()}
  def verify(message, sig, recipient \\ nil)

  def verify(_message, sig, _recipient) when byte_size(sig) < 4 do
    {:error, "signature too short"}
  end

  def verify(message, <<@version, rest::binary>>, recipient) do
    with {:ok, signer, actual_recipient, key_id, signature_der} <- parse_sig_body(rest, recipient) do
      key_id_b64 = Base.encode64(key_id)
      invoice_number = "2-message signing-#{key_id_b64}"

      with {:ok, signing_key} <- PublicKey.derive_child(signer, actual_recipient, invoice_number) do
        hashed = Crypto.sha256(message)
        {:ok, PublicKey.verify(signing_key, hashed, signature_der)}
      end
    end
  end

  def verify(_message, <<version::binary-size(4), _::binary>>, _recipient) do
    {:error, "message version mismatch: Expected #{Base.encode16(@version, case: :lower)}, received #{Base.encode16(version, case: :lower)}"}
  end

  # --- Private ---

  defp resolve_verifier(nil) do
    {:ok, pk} = PrivateKey.from_bytes(@anyone_key_bytes)
    {PrivateKey.to_public_key(pk), true}
  end

  defp resolve_verifier(%PublicKey{} = pub), do: {pub, false}

  defp parse_sig_body(data, _recipient) when byte_size(data) < 34 do
    {:error, "signature too short for sender pubkey"}
  end

  defp parse_sig_body(<<sender_bytes::binary-size(33), 0x00, rest::binary>>, _recipient) do
    # Anyone mode
    with {:ok, signer} <- PublicKey.from_bytes(sender_bytes) do
      {:ok, anyone_priv} = PrivateKey.from_bytes(@anyone_key_bytes)
      actual = anyone_priv

      if byte_size(rest) < 32 do
        {:error, "signature too short for key ID"}
      else
        <<key_id::binary-size(32), signature_der::binary>> = rest
        {:ok, signer, actual, key_id, signature_der}
      end
    end
  end

  defp parse_sig_body(<<sender_bytes::binary-size(33), verifier_bytes::binary-size(33), rest::binary>>, recipient) do
    with {:ok, signer} <- PublicKey.from_bytes(sender_bytes) do
      case recipient do
        nil ->
          {:error, "this signature can only be verified with knowledge of a specific private key. The associated public key is: #{Base.encode16(verifier_bytes, case: :lower)}"}

        %PrivateKey{} = r ->
          actual_pub = PrivateKey.to_public_key(r).point

          if verifier_bytes != actual_pub do
            {:error, "the recipient public key is #{Base.encode16(actual_pub, case: :lower)} but the signature requires the recipient to have public key #{Base.encode16(verifier_bytes, case: :lower)}"}
          else
            if byte_size(rest) < 32 do
              {:error, "signature too short for key ID"}
            else
              <<key_id::binary-size(32), signature_der::binary>> = rest
              {:ok, signer, r, key_id, signature_der}
            end
          end
      end
    end
  end

  defp parse_sig_body(_, _), do: {:error, "signature too short for verifier"}
end
