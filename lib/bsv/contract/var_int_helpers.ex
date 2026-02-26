defmodule BSV.Contract.VarIntHelpers do
  @moduledoc """
  Script-level VarInt helpers for `BSV.Contract` modules.

  VarInts are commonly used in Bitcoin scripts to encode variable-length data.
  These helpers generate script opcodes that extract or trim VarInt prefixes
  at runtime on the script stack.

  ## Usage

      import BSV.Contract.VarIntHelpers

  Or through `use BSV.Contract` (auto-imported).
  """

  alias BSV.Contract
  import BSV.Contract.Helpers

  @doc """
  Assuming the top stack item is a VarInt-prefixed binary, extract the VarInt
  number and place it on top of the stack.

  The original element is **not** removed (it is duplicated first).
  """
  @spec get_varint(Contract.t()) :: Contract.t()
  def get_varint(%Contract{} = ctx) do
    ctx
    |> op_dup()
    |> varint_switch(&do_get_varint/2)
  end

  defp do_get_varint(ctx, 1) do
    ctx
    |> op_nip()
    |> decode_uint()
  end

  defp do_get_varint(ctx, bytes) do
    ctx
    |> op_drop()
    |> push(bytes)
    |> op_split()
    |> op_drop()
    |> decode_uint()
  end

  @doc """
  Assuming the top stack item is a VarInt-prefixed binary, extract the VarInt
  data and place it on top of the stack.

  The original element is removed. Any remaining data is second on the stack.
  """
  @spec read_varint(Contract.t()) :: Contract.t()
  def read_varint(%Contract{} = ctx) do
    varint_switch(ctx, &do_read_varint/2)
  end

  defp do_read_varint(ctx, 1) do
    ctx
    |> decode_uint()
    |> op_split()
    |> op_swap()
  end

  defp do_read_varint(ctx, bytes) do
    ctx
    |> op_drop()
    |> push(bytes)
    |> op_split()
    |> op_swap()
    |> decode_uint()
    |> op_split()
    |> op_swap()
  end

  @doc """
  Assuming the top stack item is a VarInt-prefixed binary, trim the VarInt
  prefix from the leading bytes.

  The original element is replaced with the data after the VarInt prefix.
  """
  @spec trim_varint(Contract.t()) :: Contract.t()
  def trim_varint(%Contract{} = ctx) do
    varint_switch(ctx, &do_trim_varint/2)
  end

  defp do_trim_varint(ctx, 1), do: op_drop(ctx)

  defp do_trim_varint(ctx, bytes) do
    ctx
    |> op_drop()
    |> trim(bytes)
  end

  # Shared VarInt prefix switch: peeks the first byte, branches on 0xFD/0xFE/0xFF
  defp varint_switch(ctx, handler) when is_function(handler, 2) do
    ctx
    |> op_1()
    |> op_split()
    |> op_swap()
    |> op_dup()
    |> push(<<253>>)
    |> op_equal()
    |> op_if(&handler.(&1, 2), fn ctx2 ->
      ctx2
      |> op_dup()
      |> push(<<254>>)
      |> op_equal()
      |> op_if(&handler.(&1, 4), fn ctx3 ->
        ctx3
        |> op_dup()
        |> push(<<255>>)
        |> op_equal()
        |> op_if(&handler.(&1, 8), &handler.(&1, 1))
      end)
    end)
  end
end
