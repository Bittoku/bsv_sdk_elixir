defmodule BSV.ARC.Error do
  @moduledoc "Error types for ARC operations."

  defexception [:type, :message, :code]

  @type t :: %__MODULE__{
          type: :http | :serialization | :rejected | :timeout,
          message: String.t(),
          code: integer() | nil
        }

  @impl true
  def message(%__MODULE__{message: msg}), do: msg
end
