defmodule BSV.Contract.OpReturn do
  @moduledoc """
  OP_RETURN output for placing arbitrary data on-chain.

  ## Lock parameters
  - `:data` — a binary or list of binaries to push after OP_FALSE OP_RETURN
  """
  use BSV.Contract

  @impl true
  def locking_script(ctx, %{data: data}) when is_list(data) do
    ctx
    |> op_false()
    |> op_return()
    |> push(data)
  end

  def locking_script(ctx, %{data: data}) when is_binary(data) do
    ctx
    |> op_false()
    |> op_return()
    |> push(data)
  end
end
