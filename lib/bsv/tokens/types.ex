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
  @moduledoc "dSTAS spending operation type."

  @type t :: :transfer | :freeze_unfreeze | :confiscation | :swap_cancellation

  @spec to_byte(t()) :: byte()
  def to_byte(:transfer), do: 1
  def to_byte(:freeze_unfreeze), do: 2
  def to_byte(:confiscation), do: 3
  def to_byte(:swap_cancellation), do: 4
end

defmodule BSV.Tokens.ActionData do
  @moduledoc "Additional data attached to a dSTAS action."

  @type t ::
          {:swap, <<_::256>>}
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
  @moduledoc "Parameters for a DSTAS output in spend operations."

  @type t :: %__MODULE__{
          satoshis: non_neg_integer(),
          owner_pkh: <<_::160>>,
          redemption_pkh: <<_::160>>,
          frozen: boolean(),
          freezable: boolean(),
          service_fields: [binary()],
          optional_data: [binary()]
        }

  defstruct [
    :satoshis,
    :owner_pkh,
    :redemption_pkh,
    frozen: false,
    freezable: true,
    service_fields: [],
    optional_data: []
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
