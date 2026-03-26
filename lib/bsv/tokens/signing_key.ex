defmodule BSV.Tokens.SigningKey do
  @moduledoc """
  Signing credentials for a UTXO — either a single key (P2PKH) or
  threshold keys with a multisig script (P2MPKH).

  ## Variants

      {:single, PrivateKey.t()}
      {:multi, [PrivateKey.t()], P2MPKH.multisig_script()}

  ## Examples

      # P2PKH signing
      signing_key = SigningKey.single(private_key)

      # 2-of-3 P2MPKH signing
      {:ok, ms} = P2MPKH.new_multisig(2, [pk1, pk2, pk3])
      signing_key = SigningKey.multi([key1, key2], ms)
  """

  alias BSV.{Crypto, PrivateKey, PublicKey}
  alias BSV.Transaction.P2MPKH

  @type t ::
          {:single, PrivateKey.t()}
          | {:multi, [PrivateKey.t()], P2MPKH.multisig_script()}

  @doc "Create a P2PKH signing key."
  @spec single(PrivateKey.t()) :: t()
  def single(%PrivateKey{} = key), do: {:single, key}

  @doc "Create a P2MPKH signing key."
  @spec multi([PrivateKey.t()], P2MPKH.multisig_script()) :: t()
  def multi(private_keys, multisig) when is_list(private_keys) do
    {:multi, private_keys, multisig}
  end

  @doc """
  Wrap a `PrivateKey` as a signing key (convenience for migration).

  Accepts either a `PrivateKey` struct or an existing `SigningKey` tuple.
  """
  @spec wrap(PrivateKey.t() | t()) :: t()
  def wrap(%PrivateKey{} = key), do: {:single, key}
  def wrap({:single, _} = sk), do: sk
  def wrap({:multi, _, _} = sk), do: sk

  @doc """
  Compute the 20-byte hash for this signing key.

  - P2PKH: HASH160 of compressed public key
  - P2MPKH: HASH160 of serialized multisig script (the MPKH)
  """
  @spec hash160(t()) :: <<_::160>>
  def hash160({:single, key}) do
    pubkey_bytes = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point)
    Crypto.hash160(pubkey_bytes)
  end

  def hash160({:multi, _keys, multisig}) do
    P2MPKH.mpkh(multisig)
  end

  @doc "Returns `true` if this is a P2MPKH signing key."
  @spec multi?(t()) :: boolean()
  def multi?({:multi, _, _}), do: true
  def multi?(_), do: false
end
