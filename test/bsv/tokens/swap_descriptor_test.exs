defmodule BSV.Tokens.SwapDescriptorTest do
  @moduledoc """
  Tests for STAS 3.0 v0.1 §6.3 recursive swap descriptor encode/parse.

  Covers:
    * No-`next` round trip (legacy 61-byte form must remain a valid
      input/output of the new encoder/parser).
    * `{:passive, <<>>}`, `{:passive, <<arbitrary>>}`, `:frozen` next
      variants.
    * One-level and three-level recursive `{:swap, descriptor}` chains.
    * Snapshot of the exact 3-level recursive var2 hex (cross-SDK
      validation vector).
    * Rejection of malformed inputs: extra bytes after a frozen marker,
      truncated inner swap.
  """
  use ExUnit.Case, async: true

  alias BSV.Tokens.SwapDescriptor

  # Distinct sentinels to make snapshot bytes recognisable.
  # Sentinel test vectors aligned with the Rust SDK reference at
  # crates/bsv-tokens/src/types.rs::swap_descriptor_three_level_recursive_round_trip_and_snapshot
  # so the 3-level snapshot hex below is byte-identical across SDKs.
  defp h1, do: :binary.copy(<<0x11>>, 32)
  defp a1, do: :binary.copy(<<0x41>>, 20)
  defp h2, do: :binary.copy(<<0x22>>, 32)
  defp a2, do: :binary.copy(<<0x42>>, 20)
  defp h3, do: :binary.copy(<<0x33>>, 32)
  defp a3, do: :binary.copy(<<0x43>>, 20)

  defp leaf,
    do: %SwapDescriptor{
      requested_script_hash: h1(),
      receive_addr: a1(),
      rate_numerator: 10,
      rate_denominator: 11,
      next: nil
    }

  describe "to_var2_bytes / parse round trip" do
    test "61-byte form (no next) round-trips byte-identically to legacy encoder" do
      d = leaf()
      bin = SwapDescriptor.to_var2_bytes(d)

      # 61 bytes total: 0x01 + 32 + 20 + 4 + 4
      assert byte_size(bin) == 61

      # Must match what the legacy encoder produces for the same fields.
      legacy =
        BSV.Tokens.Script.Stas3Builder.encode_swap_action_data(%{
          requested_script_hash: h1(),
          requested_pkh: a1(),
          rate_numerator: 10,
          rate_denominator: 11
        })

      assert bin == legacy

      assert {:ok, ^d} = SwapDescriptor.parse(bin)
    end

    test "next = {:passive, <<>>} (just the 0x00 marker, no body)" do
      d = %{leaf() | next: {:passive, <<>>}}
      bin = SwapDescriptor.to_var2_bytes(d)
      assert byte_size(bin) == 62
      assert binary_part(bin, 61, 1) == <<0x00>>
      assert {:ok, ^d} = SwapDescriptor.parse(bin)
    end

    test "next = {:passive, <<16-byte payload>>}" do
      payload = :binary.copy(<<0xAB>>, 16)
      d = %{leaf() | next: {:passive, payload}}
      bin = SwapDescriptor.to_var2_bytes(d)
      assert byte_size(bin) == 61 + 1 + 16
      assert {:ok, ^d} = SwapDescriptor.parse(bin)
    end

    test "next = :frozen" do
      d = %{leaf() | next: :frozen}
      bin = SwapDescriptor.to_var2_bytes(d)
      assert byte_size(bin) == 62
      assert binary_part(bin, 61, 1) == <<0x02>>
      assert {:ok, ^d} = SwapDescriptor.parse(bin)
    end

    test "one-level recursive {:swap, ...}" do
      inner = %SwapDescriptor{
        requested_script_hash: h2(),
        receive_addr: a2(),
        rate_numerator: 20,
        rate_denominator: 21,
        next: nil
      }

      d = %{leaf() | next: {:swap, inner}}
      bin = SwapDescriptor.to_var2_bytes(d)

      # 61 (head) + 60 (inner body, no leading 0x01)
      assert byte_size(bin) == 61 + 60
      assert {:ok, ^d} = SwapDescriptor.parse(bin)
    end

    test "three-level recursive {:swap, {:swap, {:swap, _}}}" do
      d = three_level_chain()
      bin = SwapDescriptor.to_var2_bytes(d)

      # 61 + 60 + 60 = 181
      assert byte_size(bin) == 181
      assert {:ok, ^d} = SwapDescriptor.parse(bin)
    end
  end

  describe "snapshot vectors (cross-SDK validation)" do
    test "three-level recursive var2 hex is pinned" do
      bin = SwapDescriptor.to_var2_bytes(three_level_chain())

      # Snapshot pinned hex (CROSS-SDK CANONICAL VECTOR).
      # Layout: 0x01 head ‖ leaf body ‖ inner body ‖ deepest body.
      # Each "body" = hash(32) ‖ addr(20) ‖ num(LE32) ‖ den(LE32).
      #   leaf:    hash=0x11*32, addr=0x41*20, num=10, den=11
      #   inner:   hash=0x22*32, addr=0x42*20, num=20, den=21
      #   deepest: hash=0x33*32, addr=0x43*20, num=30, den=31
      # Inner and deepest bodies omit the leading 0x01 per spec §6.3.
      # Must match Rust bsv-sdk-rust types::swap_descriptor_three_level_recursive_round_trip_and_snapshot.
      expected_hex =
        "01" <>
          dup_hex("11", 32) <>
          dup_hex("41", 20) <>
          "0a000000" <>
          "0b000000" <>
          dup_hex("22", 32) <>
          dup_hex("42", 20) <>
          "14000000" <>
          "15000000" <>
          dup_hex("33", 32) <> dup_hex("43", 20) <> "1e000000" <> "1f000000"

      assert Base.encode16(bin, case: :lower) == expected_hex
    end
  end

  describe "rejection of malformed inputs" do
    test "missing leading 0x01 action byte" do
      # Build something that looks like a body but lacks the action byte.
      bin = binary_part(SwapDescriptor.to_var2_bytes(leaf()), 1, 60)
      assert {:error, _} = SwapDescriptor.parse(bin)
    end

    test "truncated header (only 50 bytes)" do
      bin = binary_part(SwapDescriptor.to_var2_bytes(leaf()), 0, 50)
      assert {:error, :truncated_swap_descriptor} = SwapDescriptor.parse(bin)
    end

    test "frozen marker followed by extra bytes is rejected" do
      # Construct: valid head ‖ 0x02 ‖ stray byte. Per spec §6.2 the
      # frozen marker is a single 0x02 byte; with extra bytes the parser
      # must reject — either explicitly as "extra bytes after frozen
      # marker" or by failing the nested-swap fallback (which requires
      # 60 bytes of body).
      malformed =
        SwapDescriptor.to_var2_bytes(leaf()) <> <<0x02, 0xFF>>

      assert match?({:error, _}, SwapDescriptor.parse(malformed))
    end

    test "truncated inner swap (only 30 bytes after head's tail)" do
      # head + 30 partial-body bytes (need 60 for an inner swap)
      malformed =
        SwapDescriptor.to_var2_bytes(leaf()) <> :binary.copy(<<0xCD>>, 30)

      assert {:error, {:invalid_nested_swap, :truncated_swap_descriptor}} =
               SwapDescriptor.parse(malformed)
    end
  end

  describe "swap_fields bridge helpers" do
    test "from_swap_fields/2 + to_swap_fields/1 round trip drops `next`" do
      fields = %{
        requested_script_hash: h1(),
        requested_pkh: a1(),
        rate_numerator: 10,
        rate_denominator: 11
      }

      d = SwapDescriptor.from_swap_fields(fields)
      assert d.next == nil
      assert SwapDescriptor.to_swap_fields(d) == fields

      d2 = SwapDescriptor.from_swap_fields(fields, :frozen)
      assert d2.next == :frozen
    end
  end

  defp three_level_chain do
    deepest = %SwapDescriptor{
      requested_script_hash: h3(),
      receive_addr: a3(),
      rate_numerator: 30,
      rate_denominator: 31,
      next: nil
    }

    inner = %SwapDescriptor{
      requested_script_hash: h2(),
      receive_addr: a2(),
      rate_numerator: 20,
      rate_denominator: 21,
      next: {:swap, deepest}
    }

    %{leaf() | next: {:swap, inner}}
  end

  defp dup_hex(byte_hex, count), do: String.duplicate(byte_hex, count)
end
