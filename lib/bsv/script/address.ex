defmodule BSV.Script.Address do
  @moduledoc """
  Bitcoin address handling for scripts.

  Supports P2PKH address generation from scripts and
  script generation from addresses.
  """

  alias BSV.Script

  @mainnet_p2pkh 0x00
  @testnet_p2pkh 0x6F

  @doc """
  Extract a P2PKH address string from a script.

  ## Examples

      iex> {:ok, script} = BSV.Script.from_hex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
      iex> BSV.Script.Address.from_script(script)
      {:ok, "1Mcd1xW8VbYBmouTaAeVKczR6PM1Ma4rjh"}
  """
  @spec from_script(Script.t(), :mainnet | :testnet) :: {:ok, String.t()} | :error
  def from_script(script, network \\ :mainnet) do
    case Script.get_pubkey_hash(script) do
      {:ok, pkh} ->
        version = if network == :mainnet, do: @mainnet_p2pkh, else: @testnet_p2pkh
        {:ok, BSV.Base58.check_encode(pkh, version)}

      :error ->
        :error
    end
  end

  @doc """
  Create a P2PKH locking script from a Base58Check address string.

  ## Examples

      iex> {:ok, script} = BSV.Script.Address.to_script("1Mcd1xW8VbYBmouTaAeVKczR6PM1Ma4rjh")
      iex> BSV.Script.is_p2pkh?(script)
      true
  """
  @spec to_script(String.t()) :: {:ok, Script.t()} | {:error, term()}
  def to_script(address) when is_binary(address) do
    case BSV.Base58.check_decode(address) do
      {:ok, {version, <<pkh::binary-size(20)>>}}
      when version in [@mainnet_p2pkh, @testnet_p2pkh] ->
        {:ok, Script.p2pkh_lock(pkh)}

      {:ok, _} ->
        {:error, :unsupported_address}

      {:error, _} = err ->
        err
    end
  end
end
