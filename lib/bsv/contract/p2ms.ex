defmodule BSV.Contract.P2MS do
  @moduledoc """
  Pay to Multi-Signature contract.

  ## Lock parameters
  - `:pubkeys` — list of 33-byte compressed public keys
  - `:threshold` — number of required signatures

  ## Unlock parameters
  - `:signatures` — list of DER-encoded signatures with sighash flag
  """
  use BSV.Contract

  @impl true
  def locking_script(ctx, %{pubkeys: pubkeys, threshold: threshold})
      when is_list(pubkeys) and is_integer(threshold) do
    ctx
    |> push(threshold)
    |> push(pubkeys)
    |> push(length(pubkeys))
    |> op_checkmultisig()
  end

  @impl true
  def unlocking_script(ctx, %{signatures: sigs}) when is_list(sigs) do
    ctx
    |> op_0()
    |> push(sigs)
  end
end
