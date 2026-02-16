defmodule BSV.Wallet.Types do
  @moduledoc """
  Core wallet types: Protocol, Counterparty, EncryptionArgs, etc.
  """

  @type security_level :: 0 | 1 | 2

  @doc "Security level 0: silent — no user notification."
  def security_level_silent, do: 0

  @doc "Security level 1: per-application notification."
  def security_level_every_app, do: 1

  @doc "Security level 2: per-application-and-counterparty notification."
  def security_level_every_app_and_counterparty, do: 2

  defmodule Protocol do
    @moduledoc "Protocol identifier with security level and name."
    @enforce_keys [:security_level, :protocol]
    defstruct [:security_level, :protocol]

    @type t :: %__MODULE__{
            security_level: BSV.Wallet.Types.security_level(),
            protocol: String.t()
          }
  end

  defmodule Counterparty do
    @moduledoc """
    Counterparty in a cryptographic operation.

    Types:
    - `:self` — the wallet's own identity key
    - `:anyone` — the well-known "anyone" key (scalar=1)
    - `:other` — a specific counterparty (requires `public_key`)
    - `:uninitialized` — default, will be resolved based on context
    """
    defstruct type: :uninitialized, public_key: nil

    @type counterparty_type :: :uninitialized | :anyone | :self | :other

    @type t :: %__MODULE__{
            type: counterparty_type(),
            public_key: BSV.PublicKey.t() | nil
          }
  end

  defmodule EncryptionArgs do
    @moduledoc "Common parameters for cryptographic operations."
    @enforce_keys [:protocol_id, :key_id, :counterparty]
    defstruct [
      :protocol_id,
      :key_id,
      :counterparty,
      privileged: false,
      privileged_reason: "",
      seek_permission: false
    ]

    @type t :: %__MODULE__{
            protocol_id: BSV.Wallet.Types.Protocol.t(),
            key_id: String.t(),
            counterparty: BSV.Wallet.Types.Counterparty.t(),
            privileged: boolean(),
            privileged_reason: String.t(),
            seek_permission: boolean()
          }
  end
end
