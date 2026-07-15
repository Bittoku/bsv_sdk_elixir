defmodule BSV.Tokens.ScriptFlags do
  @moduledoc """
  STAS 3.0 flags field (spec §5.2.2 + §15).

  The flags field is a single byte embedded in the trailing metadata of a STAS
  3.0 locking script, immediately after the redemption address/MPKH. Each bit
  enables an optional capability that is set at issuance and cannot be changed.

  ## Bit Layout

  | Bit | Mask   | Flag            | Service field? | Effect                              |
  |-----|--------|-----------------|----------------|-------------------------------------|
  | 0   | `0x01` | `freezable`     | yes (authority)| freeze/unfreeze by authority         |
  | 1   | `0x02` | `confiscatable` | yes (authority)| confiscation by authority             |
  | 2   | `0x04` | `nft`           | no             | non-fungible: exactly one output/spend (§15.1) |
  | 3   | `0x08` | `augmentable`   | no             | append-only data-augmentability (§15.2), NFT-only |

  When a freeze/confiscate flag is enabled, a corresponding **service field**
  follows the flags in the trailing metadata, containing the authority
  address/MPKH; service fields appear right-to-left relative to the flag bits.
  The NFT and AUGMENTABLE bits add no service fields.

  ## Encoding

  The flags field is a single canonical byte (spec §15.5). Per §15.5 a
  multi-byte flags field is read by its **last** byte (e.g. `aa0c` → capabilities
  active, `0c00` → none); an empty field means no capabilities. Do NOT use
  `OP_1`–`OP_16` for the flags field — use pushdata encoding.

  Mirrors `Stas3Flags` in the Rust SDK.
  """

  import Bitwise

  @freezable 0x01
  @confiscatable 0x02
  @nft 0x04
  @augmentable 0x08

  @type t :: %__MODULE__{
          freezable: boolean(),
          confiscatable: boolean(),
          nft: boolean(),
          augmentable: boolean()
        }

  defstruct freezable: false, confiscatable: false, nft: false, augmentable: false

  @doc "Bit 0 mask — freezable (spec §5.2.2)."
  @spec freezable_mask() :: 0x01
  def freezable_mask, do: @freezable

  @doc "Bit 1 mask — confiscatable (spec §5.2.2)."
  @spec confiscatable_mask() :: 0x02
  def confiscatable_mask, do: @confiscatable

  @doc "Bit 2 mask — NFT (spec §15.1)."
  @spec nft_mask() :: 0x04
  def nft_mask, do: @nft

  @doc "Bit 3 mask — augmentable (spec §15.2)."
  @spec augmentable_mask() :: 0x08
  def augmentable_mask, do: @augmentable

  @doc "Pack the set capability bits into the single flags byte."
  @spec to_byte(t()) :: byte()
  def to_byte(%__MODULE__{} = flags) do
    if(flags.freezable, do: @freezable, else: 0) |||
      if(flags.confiscatable, do: @confiscatable, else: 0) |||
      if(flags.nft, do: @nft, else: 0) |||
      if flags.augmentable, do: @augmentable, else: 0
  end

  @doc """
  Encode flags to the flags-field push payload (the single canonical byte, spec
  §15.5). Feed the result to the locking-script builder's `flags` argument.
  """
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{} = flags), do: <<to_byte(flags)>>

  @doc """
  Decode a flags-field value. Per spec §15.5 a multi-byte flags field is read by
  its **last** byte (e.g. `aa0c` → capabilities active, `0c00` → none); an empty
  field means no capabilities.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, :invalid_flags}
  def decode(<<>>), do: {:ok, %__MODULE__{}}

  def decode(bytes) when is_binary(bytes) do
    byte = :binary.last(bytes)

    {:ok,
     %__MODULE__{
       freezable: (byte &&& @freezable) != 0,
       confiscatable: (byte &&& @confiscatable) != 0,
       nft: (byte &&& @nft) != 0,
       augmentable: (byte &&& @augmentable) != 0
     }}
  end

  def decode(_), do: {:error, :invalid_flags}

  @doc """
  Validate the capability combination for a *new issuance*.

  AUGMENTABLE is meaningful only alongside NFT (spec §15.2); a standalone
  AUGMENTABLE bit is inert on-chain, so this rejects it as a likely error.
  Decoding an existing on-chain frame does not validate — the engine simply
  ignores an inert bit.
  """
  @spec validate(t()) :: :ok | {:error, :augmentable_requires_nft}
  def validate(%__MODULE__{augmentable: true, nft: false}),
    do: {:error, :augmentable_requires_nft}

  def validate(%__MODULE__{}), do: :ok

  @doc """
  Returns the number of authority service fields these flags imply (one each for
  freezable and confiscatable; NFT and AUGMENTABLE add none, §15).
  """
  @spec service_field_count(t()) :: non_neg_integer()
  def service_field_count(%__MODULE__{freezable: f, confiscatable: c}) do
    if(f, do: 1, else: 0) + if c, do: 1, else: 0
  end
end
