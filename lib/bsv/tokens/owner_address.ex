defmodule BSV.Tokens.OwnerAddress do
  @moduledoc """
  Owner address for token destinations — either a standard address (P2PKH)
  or a 20-byte MPKH (P2MPKH).

  Both produce the same 20-byte hash in the locking script. The difference
  is in how the unlocking script is constructed at spend time.

  ## Variants

      {:address, String.t()}      — Base58Check address string
      {:mpkh, <<_::160>>}         — 20-byte HASH160 of multisig script
  """

  alias BSV.Transaction.P2MPKH

  @type t ::
          {:address, String.t()}
          | {:mpkh, <<_::160>>}

  @doc "Create from a Base58Check address string."
  @spec from_address(String.t()) :: t()
  def from_address(addr) when is_binary(addr), do: {:address, addr}

  @doc "Create from a 20-byte MPKH."
  @spec from_mpkh(<<_::160>>) :: t()
  def from_mpkh(<<mpkh::binary-size(20)>>), do: {:mpkh, mpkh}

  @doc "Create from a multisig script."
  @spec from_multisig(P2MPKH.multisig_script()) :: t()
  def from_multisig(ms), do: {:mpkh, P2MPKH.mpkh(ms)}

  @doc """
  Get the 20-byte hash (PKH or MPKH).
  """
  @spec hash(t()) :: {:ok, <<_::160>>} | {:error, term()}
  def hash({:mpkh, mpkh}), do: {:ok, mpkh}

  def hash({:address, addr}) do
    case BSV.Base58.check_decode(addr) do
      {:ok, {_version, <<pkh::binary-size(20)>>}} -> {:ok, pkh}
      _ -> {:error, :invalid_address}
    end
  end
end
