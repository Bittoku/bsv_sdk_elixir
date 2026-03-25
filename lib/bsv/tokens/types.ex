defmodule BSV.Tokens.Payment do
  @moduledoc "A UTXO payment input for token transactions."

  @type t :: %__MODULE__{
          txid: binary(),
          vout: non_neg_integer(),
          satoshis: non_neg_integer(),
          locking_script: BSV.Script.t(),
          private_key: BSV.PrivateKey.t()
        }

  defstruct [:txid, :vout, :satoshis, :locking_script, :private_key]
end

defmodule BSV.Tokens.Destination do
  @moduledoc "A destination for token transfer."

  @type t :: %__MODULE__{
          address: String.t(),
          satoshis: non_neg_integer()
        }

  defstruct [:address, :satoshis]
end

defmodule BSV.Tokens.DstasSpendType do
  @moduledoc """
  dSTAS spending operation type.

  **Deprecated:** Use `BSV.Tokens.SpendType` instead. This module delegates
  to `SpendType` for backward compatibility.
  """

  @type t :: BSV.Tokens.SpendType.t()

  @doc "Convert a spend type atom to its wire-format byte value."
  defdelegate to_byte(spend_type), to: BSV.Tokens.SpendType
end

defmodule BSV.Tokens.ActionData do
  @moduledoc """
  Additional data attached to a dSTAS action.

  ## Swap Variant

  The swap variant carries the full 61-byte swap leg structure:
  - `requested_script_hash` (32 bytes) — SHA256 of counterparty's locking script tail
  - `requested_pkh` (20 bytes) — requested recipient public key hash
  - `rate_numerator` (uint32 LE) — exchange rate numerator
  - `rate_denominator` (uint32 LE) — exchange rate denominator

  Special case: both numerator=0 and denominator=0 indicates swap cancellation.
  """

  @type swap_fields :: %{
          requested_script_hash: <<_::256>>,
          requested_pkh: <<_::160>>,
          rate_numerator: non_neg_integer(),
          rate_denominator: non_neg_integer()
        }

  @type t ::
          {:swap, swap_fields()}
          | {:custom, binary()}
end

defmodule BSV.Tokens.DstasLockingParams do
  @moduledoc "Parameters for constructing a dSTAS locking script."

  @type t :: %__MODULE__{
          address: String.t(),
          spend_type: BSV.Tokens.DstasSpendType.t(),
          action_data: BSV.Tokens.ActionData.t() | nil
        }

  defstruct [:address, :spend_type, action_data: nil]
end

defmodule BSV.Tokens.DstasDestination do
  @moduledoc "A destination specific to dSTAS token operations."

  @type t :: %__MODULE__{
          address: String.t(),
          satoshis: non_neg_integer(),
          spend_type: BSV.Tokens.DstasSpendType.t(),
          action_data: BSV.Tokens.ActionData.t() | nil
        }

  defstruct [:address, :satoshis, :spend_type, action_data: nil]
end

defmodule BSV.Tokens.DstasOutputParams do
  @moduledoc """
  Parameters for a DSTAS output in spend operations.

  The optional `action_data` field allows encoding swap action data or custom
  data into the output's locking script. For swap principal outputs, this should
  be `nil` (neutral marker). For swap remainder outputs, this should inherit
  from the origin leg's action data.
  """

  @type t :: %__MODULE__{
          satoshis: non_neg_integer(),
          owner_pkh: <<_::160>>,
          redemption_pkh: <<_::160>>,
          frozen: boolean(),
          freezable: boolean(),
          confiscatable: boolean(),
          service_fields: [binary()],
          optional_data: [binary()],
          action_data: BSV.Tokens.ActionData.t() | nil
        }

  defstruct [
    :satoshis,
    :owner_pkh,
    :redemption_pkh,
    frozen: false,
    freezable: true,
    confiscatable: false,
    service_fields: [],
    optional_data: [],
    action_data: nil
  ]
end

defmodule BSV.Tokens.TokenInput do
  @moduledoc "A token input for DSTAS spend operations."

  @type t :: %__MODULE__{
          txid: binary(),
          vout: non_neg_integer(),
          satoshis: non_neg_integer(),
          locking_script: BSV.Script.t(),
          private_key: BSV.PrivateKey.t()
        }

  defstruct [:txid, :vout, :satoshis, :locking_script, :private_key]
end
