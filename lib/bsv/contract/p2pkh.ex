defmodule BSV.Contract.P2PKH do
  @moduledoc """
  Pay to Public Key Hash contract.

  ## Lock parameters
  - `:pubkey_hash` — 20-byte public key hash

  ## Unlock parameters
  - `:signature` — DER-encoded signature with sighash flag appended
  - `:pubkey` — 33-byte compressed public key
  """
  use BSV.Contract

  @impl true
  def locking_script(ctx, %{pubkey_hash: pkh}) when byte_size(pkh) == 20 do
    ctx
    |> op_dup()
    |> op_hash160()
    |> push(pkh)
    |> op_equalverify()
    |> op_checksig()
  end

  @impl true
  def unlocking_script(ctx, %{signature: sig, pubkey: pubkey}) do
    ctx
    |> push(sig)
    |> push(pubkey)
  end
end
