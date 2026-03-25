defmodule BSV.Tokens.ScriptFlags do
  @moduledoc """
  STAS protocol flags field.

  The flags field is embedded in the trailing metadata of a STAS locking script,
  immediately after the redemption address/MPKH. Each bit enables an optional
  administrative capability that is set at issuance and cannot be changed.

  ## Bit Layout

  | Bit | Flag            | Effect                                      |
  |-----|-----------------|---------------------------------------------|
  | 0   | `freezable`     | Enables freeze/unfreeze by authority         |
  | 1   | `confiscatable` | Enables confiscation by authority             |

  When a flag is enabled, a corresponding **service field** follows the flags
  in the trailing metadata, containing the authority address/MPKH for that
  capability. Service fields appear left-to-right in the opposite order of the
  flag bits (right-to-left).

  ## Encoding

  The flags field is always present unless no data follows the redemption PKH.
  Use `OP_0` (0x00) or `<<0x01, 0x00>>` for default (no flags). Do NOT use
  `OP_1`–`OP_16` for the flags field — use pushdata encoding.
  """

  @type t :: %__MODULE__{
          freezable: boolean(),
          confiscatable: boolean()
        }

  import Bitwise

  defstruct freezable: false, confiscatable: false

  @doc """
  Encode flags to a binary for embedding in a locking script.

  Returns a binary where bit 0 = freezable, bit 1 = confiscatable.
  """
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{freezable: freezable, confiscatable: confiscatable}) do
    byte =
      (if freezable, do: 0x01, else: 0x00) |||
        (if confiscatable, do: 0x02, else: 0x00)

    <<byte>>
  end

  @doc """
  Decode a flags binary into a `ScriptFlags` struct.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, :invalid_flags}
  def decode(<<byte, _rest::binary>>) do
    {:ok,
     %__MODULE__{
       freezable: (byte &&& 0x01) != 0,
       confiscatable: (byte &&& 0x02) != 0
     }}
  end

  def decode(<<>>), do: {:ok, %__MODULE__{}}
  def decode(_), do: {:error, :invalid_flags}

  @doc """
  Returns the number of service fields expected for the given flags.
  """
  @spec service_field_count(t()) :: non_neg_integer()
  def service_field_count(%__MODULE__{freezable: f, confiscatable: c}) do
    (if f, do: 1, else: 0) + (if c, do: 1, else: 0)
  end
end
