defmodule BSV.Tokens.Stas3.ValidateTest do
  @moduledoc """
  Error-path coverage for STAS 3.0 v0.1 §9 build-time enforcement.

  Each negative test triggers exactly one of the documented error atoms:

    * §9.2 — `:freeze_output_count`, `:freeze_field_drift`, `:freeze_flag_not_set`
    * §9.3 — `:confiscate_flag_not_set`
    * §9.4 — `:swap_cancel_missing_descriptor`,
             `:swap_cancel_output_count`,
             `:swap_cancel_owner_mismatch`
  """
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Stas3Builder
  alias BSV.Tokens.ScriptFlags
  alias BSV.Tokens.Stas3.Validate
  alias BSV.Tokens.SwapDescriptor

  defp pkh(b), do: :binary.copy(<<b>>, 20)

  defp script(owner, redemption, flags, action_data) do
    {:ok, s} =
      Stas3Builder.build_stas3_locking_script(
        owner,
        redemption,
        action_data,
        false,
        flags,
        [],
        []
      )

    s
  end

  defp ti(owner, redemption, flags), do: ti(owner, redemption, flags, nil)

  defp ti(owner, redemption, flags, action_data) do
    %{locking_script: script(owner, redemption, flags, action_data)}
  end

  defp dest(owner, redemption \\ nil) do
    %{owner_pkh: owner, redemption_pkh: redemption}
  end

  # ── §9.2 freeze ──────────────────────────────────────────────────────

  test "freeze rejects when destinations != 1 (output_count)" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    input = ti(owner, redemption, %ScriptFlags{freezable: true})

    assert {:error, :freeze_output_count} = Validate.freeze(input, [])

    assert {:error, :freeze_output_count} =
             Validate.freeze(input, [dest(owner, redemption), dest(owner, redemption)])
  end

  test "freeze rejects when input flag bit 0 (FREEZABLE) is not set" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    # CONFISCATABLE only — FREEZABLE missing
    input = ti(owner, redemption, %ScriptFlags{freezable: false, confiscatable: true})

    assert {:error, :freeze_flag_not_set} =
             Validate.freeze(input, [dest(owner, redemption)])
  end

  test "freeze rejects field drift (owner mismatch)" do
    owner = pkh(0x01)
    drifted = pkh(0xFF)
    redemption = pkh(0x02)
    input = ti(owner, redemption, %ScriptFlags{freezable: true})

    assert {:error, :freeze_field_drift} =
             Validate.freeze(input, [dest(drifted, redemption)])
  end

  test "freeze rejects field drift (redemption mismatch)" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    drifted = pkh(0xEE)
    input = ti(owner, redemption, %ScriptFlags{freezable: true})

    assert {:error, :freeze_field_drift} =
             Validate.freeze(input, [dest(owner, drifted)])
  end

  test "freeze accepts identical owner/redemption with FREEZABLE flag" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    input = ti(owner, redemption, %ScriptFlags{freezable: true})

    assert :ok = Validate.freeze(input, [dest(owner, redemption)])
  end

  # ── §9.3 confiscation ────────────────────────────────────────────────

  test "confiscation rejects when CONFISCATABLE flag not set" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    # FREEZABLE only — CONFISCATABLE missing
    input = ti(owner, redemption, %ScriptFlags{freezable: true})

    assert {:error, :confiscate_flag_not_set} = Validate.confiscation(input)
  end

  test "confiscation accepts when CONFISCATABLE flag set" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    input = ti(owner, redemption, %ScriptFlags{freezable: true, confiscatable: true})

    assert :ok = Validate.confiscation(input)
  end

  # ── §9.4 swap cancellation ────────────────────────────────────────────

  test "swap_cancel rejects when input has no swap descriptor" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    # Plain UTXO — no swap descriptor in var2
    input = ti(owner, redemption, %ScriptFlags{freezable: true})

    assert {:error, :swap_cancel_missing_descriptor} =
             Validate.swap_cancel(input, [dest(owner)])
  end

  test "swap_cancel rejects when destinations != 1 (output_count)" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    receive_addr = pkh(0xAB)

    descriptor = %SwapDescriptor{
      requested_script_hash: :binary.copy(<<0x77>>, 32),
      receive_addr: receive_addr,
      rate_numerator: 1,
      rate_denominator: 1
    }

    input = ti(owner, redemption, %ScriptFlags{freezable: true}, {:swap, descriptor})

    assert {:error, :swap_cancel_output_count} = Validate.swap_cancel(input, [])
  end

  test "swap_cancel rejects when destination owner != input.var2.receiveAddr" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    receive_addr = pkh(0xAB)
    wrong_owner = pkh(0xCD)

    descriptor = %SwapDescriptor{
      requested_script_hash: :binary.copy(<<0x77>>, 32),
      receive_addr: receive_addr,
      rate_numerator: 1,
      rate_denominator: 1
    }

    input = ti(owner, redemption, %ScriptFlags{freezable: true}, {:swap, descriptor})

    assert {:error, :swap_cancel_owner_mismatch} =
             Validate.swap_cancel(input, [dest(wrong_owner)])
  end

  test "swap_cancel accepts when output owner equals receive_addr" do
    owner = pkh(0x01)
    redemption = pkh(0x02)
    receive_addr = pkh(0xAB)

    descriptor = %SwapDescriptor{
      requested_script_hash: :binary.copy(<<0x77>>, 32),
      receive_addr: receive_addr,
      rate_numerator: 1,
      rate_denominator: 1
    }

    input = ti(owner, redemption, %ScriptFlags{freezable: true}, {:swap, descriptor})

    assert :ok = Validate.swap_cancel(input, [dest(receive_addr)])
  end
end
