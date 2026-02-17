defmodule BSV.JungleBus.Error do
  @moduledoc "Error types for JungleBus operations."

  defexception [:type, :message, :status_code]

  @type t :: %__MODULE__{
          type: :http | :serialization | :server_error | :not_found,
          message: String.t(),
          status_code: non_neg_integer() | nil
        }

  @impl true
  def message(%__MODULE__{message: msg}), do: msg
end
