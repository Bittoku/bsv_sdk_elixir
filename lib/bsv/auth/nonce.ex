defmodule BSV.Auth.Nonce do
  @moduledoc """
  Cryptographic nonce creation and verification for auth protocols.

  A nonce is `base64(random_16_bytes || HMAC(random_16_bytes))`.
  """

  alias BSV.Wallet.ProtoWallet
  alias BSV.Wallet.Types.{Protocol, Counterparty, EncryptionArgs}

  @doc "Create a cryptographic nonce derived from the wallet."
  @spec create(ProtoWallet.t(), Counterparty.t()) :: {:ok, String.t()} | {:error, String.t()}
  def create(%ProtoWallet{} = wallet, %Counterparty{} = counterparty) do
    random = :crypto.strong_rand_bytes(16)

    enc = %EncryptionArgs{
      protocol_id: %Protocol{security_level: 1, protocol: "server hmac"},
      key_id: random |> :binary.bin_to_list() |> to_string(),
      counterparty: counterparty
    }

    case ProtoWallet.create_hmac(wallet, enc, random) do
      {:ok, hmac} ->
        {:ok, Base.encode64(random <> hmac)}

      error ->
        error
    end
  end

  @doc "Verify that a nonce was derived from the given wallet."
  @spec verify(String.t(), ProtoWallet.t(), Counterparty.t()) :: {:ok, boolean()} | {:error, String.t()}
  def verify(nonce, %ProtoWallet{} = wallet, %Counterparty{} = counterparty) do
    case Base.decode64(nonce) do
      {:ok, <<data::binary-size(16), hmac::binary-size(32)>>} ->
        enc = %EncryptionArgs{
          protocol_id: %Protocol{security_level: 1, protocol: "server hmac"},
          key_id: data |> :binary.bin_to_list() |> to_string(),
          counterparty: counterparty
        }

        ProtoWallet.verify_hmac(wallet, enc, data, hmac)

      {:ok, _} ->
        {:error, "invalid nonce length"}

      :error ->
        {:error, "invalid base64 nonce"}
    end
  end
end
