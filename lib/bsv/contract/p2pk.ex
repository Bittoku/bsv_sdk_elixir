defmodule BSV.Contract.P2PK do
  @moduledoc """
  Pay to Public Key contract.

  ## Lock parameters
  - `:pubkey` — 33-byte compressed public key

  ## Unlock parameters
  - `:signature` — DER-encoded signature with sighash flag appended
  """
  use BSV.Contract

  @impl true
  def locking_script(ctx, %{pubkey: pubkey}) when is_binary(pubkey) do
    ctx
    |> push(pubkey)
    |> op_checksig()
  end

  @impl true
  def unlocking_script(ctx, %{signature: sig}) do
    push(ctx, sig)
  end
end
