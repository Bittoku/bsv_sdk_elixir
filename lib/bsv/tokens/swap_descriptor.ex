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

  ## `next` disambiguation (note 2231 §4)

  A nested swap body carries no length prefix or tag — the cross-SDK §15
  golden vectors pin that raw layout — so the decoder cannot key on a leading
  action byte to tell a nested swap apart from a passive/frozen tail (a nested
  `requestedScriptHash` beginning `0x00` or `0x02` would otherwise be misread
  as passive/frozen). Decoding is therefore **length-based and deterministic**:

    * empty tail                    → `nil`
    * tail length `>= 60`           → nested swap body (`{:swap, _}`)
    * tail is exactly `<<0x02>>`    → `:frozen`
    * short tail (1..59) led by `0x00` → `{:passive, rest}`
    * any other short tail          → malformed (`{:invalid_nested_swap, _}`)

  This makes nested descriptors round-trip for every hash first byte while
  keeping the golden vectors byte-identical. The trade-off: a `{:passive, _}`
  payload must be `< 59` bytes (whole tail `< 60`) so it can never collide with
  a bare 60-byte nested body — the encoder enforces this and raises otherwise.

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

  # A passive `next` push encodes as `0x00 <> payload`. The whole tail MUST
  # stay shorter than a bare swap body (60 bytes) so the length-based decoder
  # (see `parse_next/1`) can never mistake it for a nested swap. Reject
  # oversized payloads loudly rather than emit bytes that would round-trip as
  # `{:swap, _}`.
  defp encode_next({:passive, bytes}) when is_binary(bytes) and byte_size(bytes) < 59 do
    <<@action_passive>> <> bytes
  end

  defp encode_next({:passive, bytes}) when is_binary(bytes) do
    raise ArgumentError,
          "passive swap-descriptor next payload must be < 59 bytes " <>
            "(got #{byte_size(bytes)}); larger payloads are indistinguishable " <>
            "from a nested swap body on decode"
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

  # Minimum length of a swap body (no leading 0x01): hash(32) + addr(20)
  # + num(4) + den(4). A `next` tail this long or longer is unambiguously a
  # nested swap; a shorter tail can only be a passive or frozen marker.
  @swap_body_min 60

  # Disambiguate the `next` tail purely by LENGTH and leading byte — never
  # by "does it happen to parse", so decoding is deterministic and a nested
  # `requested_script_hash` beginning with any byte (0x00 / 0x02 included)
  # round-trips (blocker fix, note 2231 §4):
  #
  #   * empty tail                       → nil
  #   * tail length >= 60                → nested swap body (recurse)
  #   * tail is exactly <<0x02>>         → :frozen
  #   * tail (len 1..59) starts 0x00     → {:passive, rest}
  #   * any other short tail             → malformed (surface the nested-swap
  #                                        parse error, i.e. :truncated_swap_descriptor)
  #
  # DIVERGENCE / LIMITATION (documented for cross-SDK arbitration): because a
  # nested swap body carries no length prefix or tag (the golden §15 vectors
  # pin that raw layout), a `{:passive, payload}` whose total tail reaches 60
  # bytes (payload >= 59 bytes) is indistinguishable from a bare nested swap
  # body and would be decoded as `{:swap, _}`. Passive `next` payloads are
  # therefore bounded to < 59 bytes; the encoder enforces this.
  defp parse_next(<<>>), do: {:ok, nil}

  defp parse_next(tail) when is_binary(tail) and byte_size(tail) >= @swap_body_min do
    case parse_swap_body(tail) do
      {:ok, descriptor} -> {:ok, {:swap, descriptor}}
      {:error, reason} -> {:error, {:invalid_nested_swap, reason}}
    end
  end

  defp parse_next(<<@action_frozen>>), do: {:ok, :frozen}

  defp parse_next(<<@action_passive, rest::binary>>),
    do: {:ok, {:passive, rest}}

  # A short tail (1..59 bytes) that is neither the frozen marker nor a passive
  # push cannot be a valid nested swap body — report it as such.
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
