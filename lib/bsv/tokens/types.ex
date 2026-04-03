defmodule BSV.Tokens.Payment do
  @moduledoc """
  A UTXO payment input for token transactions.

  The `signing_key` field accepts a `BSV.Tokens.SigningKey.t()`:
  - `{:single, PrivateKey.t()}` for P2PKH
  - `{:multi, [PrivateKey.t()], multisig_script}` for P2MPKH

  For backward compatibility, the `private_key` field is still accepted but
  deprecated — use `signing_key` instead.
  """

  @type t :: %__MODULE__{
          txid: binary(),
          vout: non_neg_integer(),
          satoshis: non_neg_integer(),
          locking_script: BSV.Script.t(),
          signing_key: BSV.Tokens.SigningKey.t(),
          private_key: BSV.PrivateKey.t() | nil
        }

  defstruct [:txid, :vout, :satoshis, :locking_script, :signing_key, :private_key]

  @doc """
  Resolve the effective signing key: prefers `signing_key`, falls back to
  wrapping `private_key` for backward compatibility.
  """
  @spec resolve_signing_key(t()) :: BSV.Tokens.SigningKey.t()
  def resolve_signing_key(%__MODULE__{signing_key: sk}) when sk != nil, do: sk

  def resolve_signing_key(%__MODULE__{private_key: pk}) when pk != nil,
    do: BSV.Tokens.SigningKey.single(pk)

  def resolve_signing_key(_), do: raise("Payment has neither signing_key nor private_key")
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
  STAS 3.0 spending operation type.

  **Deprecated:** Use `BSV.Tokens.SpendType` instead. This module delegates
  to `SpendType` for backward compatibility.
  """

  @type t :: BSV.Tokens.SpendType.t()

  @doc "Convert a spend type atom to its wire-format byte value."
  defdelegate to_byte(spend_type), to: BSV.Tokens.SpendType
end

defmodule BSV.Tokens.ActionData do
  @moduledoc """
  Additional data attached to a STAS 3.0 action.

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
  @moduledoc "Parameters for constructing a STAS 3.0 locking script."

  @type t :: %__MODULE__{
          address: String.t(),
          spend_type: BSV.Tokens.DstasSpendType.t(),
          action_data: BSV.Tokens.ActionData.t() | nil
        }

  defstruct [:address, :spend_type, action_data: nil]
end

defmodule BSV.Tokens.DstasDestination do
  @moduledoc "A destination specific to STAS 3.0 token operations."

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
  Parameters for a STAS 3.0 output in spend operations.

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
  @moduledoc """
  A token input for STAS 3.0 spend operations.

  The `signing_key` field accepts a `BSV.Tokens.SigningKey.t()`.
  For backward compatibility, `private_key` is still accepted but deprecated.
  """

  @type t :: %__MODULE__{
          txid: binary(),
          vout: non_neg_integer(),
          satoshis: non_neg_integer(),
          locking_script: BSV.Script.t(),
          signing_key: BSV.Tokens.SigningKey.t(),
          private_key: BSV.PrivateKey.t() | nil
        }

  defstruct [:txid, :vout, :satoshis, :locking_script, :signing_key, :private_key]

  @doc "Resolve the effective signing key."
  @spec resolve_signing_key(t()) :: BSV.Tokens.SigningKey.t()
  def resolve_signing_key(%__MODULE__{signing_key: sk}) when sk != nil, do: sk

  def resolve_signing_key(%__MODULE__{private_key: pk}) when pk != nil,
    do: BSV.Tokens.SigningKey.single(pk)

  def resolve_signing_key(_), do: raise("TokenInput has neither signing_key nor private_key")
end
