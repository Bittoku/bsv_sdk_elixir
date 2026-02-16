defmodule BSV.Wallet.Error do
  @moduledoc """
  Wallet-specific error types.
  """

  defexception [:message]

  @type t :: %__MODULE__{message: String.t()}
end
