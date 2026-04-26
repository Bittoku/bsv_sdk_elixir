defmodule BSV.Tokens.SwapDescriptor do
  @moduledoc """
  STAS 3.0 v0.1 §6.3 swap descriptor — the canonical, recursive form of the
  `var2` payload pushed by an atomic-swap STAS UTXO (action byte `0x01`).

  Wire layout (minimum 61 bytes):

      offset  0  : action            = 0x01           1 B
      offset  1  : requestedScriptHash (SHA256)      32 B
      offset 33  : receiveAddr        (HASH160)      20 B
      offset 53  : rateNumerator       u32 LE         4 B
      offset 57  : rateDenominator     u32 LE         4 B
      offset 61  : next                              variable, optional

  The `next` field, when present, is the var2 value that the maker requires
  the taker to install on the maker's remainder UTXO after the swap is fully
  or partially consumed (spec §6.3, §9.5). It can be:

    * absent (zero bytes after the 61-byte head)            → `next = nil`
    * a passive var2 push (action byte `0x00` + arbitrary)  → `{:passive, bytes}`
    * the frozen marker (single byte `0x02`)                → `:frozen`
    * another swap descriptor BUT with the leading `0x01`
      action byte STRIPPED (per spec §6.3:
      "Encoding is the same as the top-level descriptor,
       minus including the leading action byte.")          → `{:swap, %SwapDescriptor{}}`

  This module implements both encoding (`to_var2_bytes/1`) and decoding
  (`parse/1`) of the full recursive structure. The legacy 61-byte non-recursive
  form continues to round-trip correctly: `to_var2_bytes/1` of a descriptor
  with `next: nil` produces exactly the same bytes that
  `BSV.Tokens.Script.Stas3Builder.encode_swap_action_data/1` would have
  produced for the equivalent `swap_fields()` map.

  Conversion helpers (`from_swap_fields/2`, `to_swap_fields/1`) bridge to the
  legacy `BSV.Tokens.ActionData.swap_fields()` map shape used elsewhere in
  the codebase.
  """

  @action_swap 0x01
  @action_passive 0x00
  @action_frozen 0x02

  @type next_value ::
          nil
          | :frozen
          | {:passive, binary()}
          | {:swap, t()}

  @type t :: %__MODULE__{
          requested_script_hash: <<_::256>>,
          receive_addr: <<_::160>>,
          rate_numerator: non_neg_integer(),
          rate_denominator: non_neg_integer(),
          next: next_value()
        }

  defstruct [
    :requested_script_hash,
    :receive_addr,
    :rate_numerator,
    :rate_denominator,
    next: nil
  ]

  # ──────────────────────────────────────────────────────────────────────
  # Encoder
  # ──────────────────────────────────────────────────────────────────────

  @doc """
  Encode a `SwapDescriptor` to its full `var2` payload, INCLUDING the
  leading `0x01` action byte.

  Returns the raw binary (61+ bytes) suitable for use as the var2 push
  body in a STAS 3.0 locking script.
  """
  @spec to_var2_bytes(t()) :: binary()
  def to_var2_bytes(%__MODULE__{} = d) do
    <<@action_swap>> <> encode_swap_body(d)
  end

  # Encode the swap body WITHOUT the leading 0x01.
  # Used both for the top-level (after prepending 0x01) and for nested
  # `{:swap, ...}` next entries (spec: "minus the leading action byte").
  defp encode_swap_body(%__MODULE__{
         requested_script_hash: <<hash::binary-size(32)>>,
         receive_addr: <<addr::binary-size(20)>>,
         rate_numerator: num,
         rate_denominator: den,
         next: next
       })
       when is_integer(num) and num >= 0 and num <= 0xFFFFFFFF and
              is_integer(den) and den >= 0 and den <= 0xFFFFFFFF do
    head =
      <<hash::binary, addr::binary, num::little-32, den::little-32>>

    head <> encode_next(next)
  end

  defp encode_next(nil), do: <<>>
  defp encode_next(:frozen), do: <<@action_frozen>>

  defp encode_next({:passive, bytes}) when is_binary(bytes) do
    <<@action_passive>> <> bytes
  end

  defp encode_next({:swap, %__MODULE__{} = d}) do
    # Spec §6.3: nested swap is encoded WITHOUT leading 0x01.
    encode_swap_body(d)
  end

  # ──────────────────────────────────────────────────────────────────────
  # Decoder
  # ──────────────────────────────────────────────────────────────────────

  @doc """
  Parse a full `var2` payload (must include the leading `0x01` action byte)
  into a `SwapDescriptor`.

  Recursively decodes the `next` chain until either:

    * the remaining bytes are exhausted (`next = nil`),
    * a `0x00` passive marker is consumed (`next = {:passive, rest}`),
    * a single-byte `0x02` frozen marker is consumed (`next = :frozen`),
    * another swap body (no leading `0x01`) is consumed
      (`next = {:swap, %SwapDescriptor{}}`).

  Returns `{:ok, descriptor}` on success or `{:error, reason}` on
  malformed input (truncated header, frozen marker followed by extra
  bytes, or a nested-swap header that does not contain 60 bytes).
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, term()}
  def parse(<<@action_swap, rest::binary>>) do
    parse_swap_body(rest)
  end

  def parse(_), do: {:error, :missing_swap_action_byte}

  # Parse a single swap body (no leading 0x01) and recursively the tail.
  defp parse_swap_body(
         <<hash::binary-size(32), addr::binary-size(20), num::little-32, den::little-32,
           tail::binary>>
       ) do
    case parse_next(tail) do
      {:ok, next} ->
        {:ok,
         %__MODULE__{
           requested_script_hash: hash,
           receive_addr: addr,
           rate_numerator: num,
           rate_denominator: den,
           next: next
         }}

      {:error, _} = err ->
        err
    end
  end

  defp parse_swap_body(_), do: {:error, :truncated_swap_descriptor}

  defp parse_next(<<>>), do: {:ok, nil}

  defp parse_next(<<@action_frozen>>), do: {:ok, :frozen}

  # Frozen marker followed by anything else is malformed: the frozen var2
  # is a single-byte payload by definition (§6.2).
  defp parse_next(<<@action_frozen, _rest::binary>>),
    do: {:error, :extra_bytes_after_frozen_marker}

  defp parse_next(<<@action_passive, rest::binary>>),
    do: {:ok, {:passive, rest}}

  # Anything else: treat as a nested swap body (no leading 0x01 per spec).
  defp parse_next(other) when is_binary(other) do
    case parse_swap_body(other) do
      {:ok, descriptor} -> {:ok, {:swap, descriptor}}
      {:error, reason} -> {:error, {:invalid_nested_swap, reason}}
    end
  end

  # ──────────────────────────────────────────────────────────────────────
  # Bridge helpers to the legacy ActionData / swap_fields shape
  # ──────────────────────────────────────────────────────────────────────

  @doc """
  Build a `SwapDescriptor` from the legacy
  `BSV.Tokens.ActionData.swap_fields()` map (which uses `:requested_pkh`
  rather than `:receive_addr`). The `next` field is taken from the second
  argument, defaulting to `nil` for full backward compatibility with the
  61-byte form.
  """
  @spec from_swap_fields(BSV.Tokens.ActionData.swap_fields(), next_value()) :: t()
  def from_swap_fields(
        %{
          requested_script_hash: hash,
          requested_pkh: pkh,
          rate_numerator: num,
          rate_denominator: den
        },
        next \\ nil
      ) do
    %__MODULE__{
      requested_script_hash: hash,
      receive_addr: pkh,
      rate_numerator: num,
      rate_denominator: den,
      next: next
    }
  end

  @doc """
  Project a `SwapDescriptor` down to the legacy
  `BSV.Tokens.ActionData.swap_fields()` map (drops the recursive `next`
  field). Useful when an existing API only consumes the 61-byte form.
  """
  @spec to_swap_fields(t()) :: BSV.Tokens.ActionData.swap_fields()
  def to_swap_fields(%__MODULE__{} = d) do
    %{
      requested_script_hash: d.requested_script_hash,
      requested_pkh: d.receive_addr,
      rate_numerator: d.rate_numerator,
      rate_denominator: d.rate_denominator
    }
  end
end
