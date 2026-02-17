defmodule BSV.JungleBus.Config do
  @moduledoc "Configuration for a JungleBus client."

  @type t :: %__MODULE__{
          server_url: String.t(),
          token: String.t() | nil,
          api_version: String.t()
        }

  defstruct server_url: "https://junglebus.gorillapool.io",
            token: nil,
            api_version: "v1"
end
