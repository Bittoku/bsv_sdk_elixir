defmodule BSV.Contract.Raw do
  @moduledoc """
  Raw script contract — wraps a pre-built `BSV.Script` for use with the contract DSL.

  ## Lock/Unlock parameters
  - `:script` — a `BSV.Script.t()` struct
  """
  use BSV.Contract

  @impl true
  def locking_script(ctx, %{script: %BSV.Script{} = script}) do
    %{ctx | script: script}
  end

  @impl true
  def unlocking_script(ctx, %{script: %BSV.Script{} = script}) do
    %{ctx | script: script}
  end
end
