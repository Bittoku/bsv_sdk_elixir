defmodule BSV.ARC.Config do
  @moduledoc "Configuration for an ARC client."

  @type t :: %__MODULE__{
          base_url: String.t(),
          api_key: String.t() | nil,
          callback_url: String.t() | nil,
          callback_token: String.t() | nil,
          wait_for_status: BSV.ARC.Types.arc_status() | nil,
          skip_fee_validation: boolean(),
          skip_script_validation: boolean(),
          skip_tx_validation: boolean(),
          cumulative_fee_validation: boolean(),
          full_status_updates: boolean(),
          max_timeout: non_neg_integer() | nil
        }

  defstruct base_url: "https://arc.taal.com/v1",
            api_key: nil,
            callback_url: nil,
            callback_token: nil,
            wait_for_status: nil,
            skip_fee_validation: false,
            skip_script_validation: false,
            skip_tx_validation: false,
            cumulative_fee_validation: false,
            full_status_updates: false,
            max_timeout: nil
end
