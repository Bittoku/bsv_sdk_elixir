defmodule BSV.Tokens.Stas3.Validate do
  @moduledoc """
  STAS 3.0 v0.1 §9 build-time enforcement helpers.

  These predicates run BEFORE signing, on the resolved input + destination
  set assembled by a factory. They catch spec violations at construction
  time so that we never produce a transaction whose engine would reject
  it on broadcast.

  ## Coverage

    * `freeze/2` — §9.2 Freeze / Unfreeze:
        - exactly one STAS output,
        - non-`var2` fields byte-identical to the input,
        - FREEZABLE flag bit set in the input's flags.

    * `confiscation/1` — §9.3 Confiscation:
        - CONFISCATABLE flag bit set in the input's flags.

    * `swap_cancel/2` — §9.4 Swap cancellation:
        - input must carry a swap descriptor (action 0x01),
        - exactly one STAS output,
        - output's owner equals the input's `var2.receiveAddr`.

  Each function returns `:ok` on success or `{:error, atom_or_tuple}` on
  failure. Error atoms are the ones documented in the brief:

    * `:freeze_output_count`, `:freeze_field_drift`, `:freeze_flag_not_set`
    * `:confiscate_flag_not_set`
    * `:swap_cancel_missing_descriptor`, `:swap_cancel_output_count`,
      `:swap_cancel_owner_mismatch`

  Per spec §9.6, these checks are applied independently — the calling
  factory chooses which to invoke based on its own intent. The §9.6
  precedence rule (Confiscation > Freeze > Swap > Regular) is informative
  for engines that must classify a spend post-hoc; in this SDK the
  factory is authoritative.
  """

  alias BSV.Script
  alias BSV.Tokens.Script.Reader
  alias BSV.Tokens.ScriptFlags

  @typedoc "A token input as understood by the STAS3 factory layer."
  @type token_input :: %{
          required(:locking_script) => Script.t(),
          optional(any) => any
        }

  @typedoc "A STAS3 destination as understood by the STAS3 factory layer."
  @type destination :: %{
          required(:owner_pkh) => <<_::160>>,
          optional(any) => any
        }

  # ── §9.2 Freeze / Unfreeze ────────────────────────────────────────────

  @doc """
  Validate a freeze (or unfreeze) build per spec §9.2.

  Requires:

    * exactly one destination (single STAS output),
    * destination's `owner_pkh` and `redemption_pkh` byte-identical to
      the input — `var2` is the only field permitted to drift,
    * input's `flags` field has the FREEZABLE bit set.
  """
  @spec freeze(token_input(), [destination()]) :: :ok | {:error, atom()}
  def freeze(token_input, destinations) do
    with :ok <- check_count(destinations, 1, :freeze_output_count),
         {:ok, fields} <- parsed_stas3_fields(token_input),
         :ok <- check_flag(fields.flags, :freezable, :freeze_flag_not_set) do
      check_freeze_field_drift(fields, hd(destinations))
    end
  end

  # ── §9.3 Confiscation ────────────────────────────────────────────────

  @doc """
  Validate a confiscation build per spec §9.3.

  Requires only that the input's `flags` field has the CONFISCATABLE bit
  set. Output count and `var2` content are unconstrained per spec.
  """
  @spec confiscation(token_input()) :: :ok | {:error, atom()}
  def confiscation(token_input) do
    with {:ok, fields} <- parsed_stas3_fields(token_input) do
      check_flag(fields.flags, :confiscatable, :confiscate_flag_not_set)
    end
  end

  # ── §9.4 Swap cancellation ───────────────────────────────────────────

  @doc """
  Validate a swap-cancellation build per spec §9.4.

  Requires:

    * input's `var2` parses as a swap descriptor (action `0x01`),
    * exactly one destination,
    * destination's `owner_pkh` equals the input's `var2.receiveAddr`.

  Authorisation against `receiveAddr` is enforced by the engine at
  spend time and is not re-checked here.
  """
  @spec swap_cancel(token_input(), [destination()]) :: :ok | {:error, atom()}
  def swap_cancel(token_input, destinations) do
    with {:ok, fields} <- parsed_stas3_fields(token_input),
         :ok <- check_swap_descriptor_present(fields),
         :ok <- check_count(destinations, 1, :swap_cancel_output_count) do
      check_swap_cancel_owner(fields, hd(destinations))
    end
  end

  # ── internals ────────────────────────────────────────────────────────

  defp parsed_stas3_fields(%{locking_script: %Script{} = script}) do
    parsed = Reader.read_locking_script(Script.to_binary(script))

    case parsed do
      %{script_type: :stas3, stas3: fields} when not is_nil(fields) ->
        {:ok, fields}

      _ ->
        {:error, :not_stas3_input}
    end
  end

  defp parsed_stas3_fields(_), do: {:error, :not_stas3_input}

  defp check_count(list, n, _) when length(list) == n, do: :ok
  defp check_count(_, _, err), do: {:error, err}

  defp check_flag(flag_bytes, which, err_atom) do
    case ScriptFlags.decode(flag_bytes) do
      {:ok, flags} ->
        case which do
          :freezable -> if flags.freezable, do: :ok, else: {:error, err_atom}
          :confiscatable -> if flags.confiscatable, do: :ok, else: {:error, err_atom}
        end

      {:error, _} ->
        {:error, err_atom}
    end
  end

  # §9.2: only `var2` may differ. We compare `owner` and `redemption`
  # explicitly and rely on the engine for full data-region equality
  # (which is enforced via the preimage trick at spend time).
  defp check_freeze_field_drift(fields, %{owner_pkh: dest_owner} = dest) do
    redemption_drift =
      case Map.get(dest, :redemption_pkh) do
        nil -> false
        rpkh -> rpkh != fields.redemption
      end

    cond do
      dest_owner != fields.owner -> {:error, :freeze_field_drift}
      redemption_drift -> {:error, :freeze_field_drift}
      true -> :ok
    end
  end

  defp check_swap_descriptor_present(%{swap_descriptor: %_{} = _}), do: :ok
  defp check_swap_descriptor_present(_), do: {:error, :swap_cancel_missing_descriptor}

  defp check_swap_cancel_owner(%{swap_descriptor: %{receive_addr: rcv}}, %{owner_pkh: dest_owner}) do
    if dest_owner == rcv, do: :ok, else: {:error, :swap_cancel_owner_mismatch}
  end
end
