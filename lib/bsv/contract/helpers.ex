defmodule BSV.Contract.Helpers do
  @moduledoc """
  Pipeline helpers for building scripts in `BSV.Contract` modules.

  When you `use BSV.Contract`, this module is automatically imported, providing:

  - `push/2` — push data or opcode onto the script
  - All standard opcodes as pipeline functions (e.g. `op_dup/1`, `op_hash160/1`)
  - `op_if/2`, `op_if/3` — flow control with callback functions
  - `each/3`, `repeat/3` — iteration helpers
  - `slice/3`, `trim/2` — stack manipulation helpers
  """

  alias BSV.Contract
  alias BSV.Script.Opcodes

  @doc "Push data (binary), an opcode tuple, or a list of items onto the script."
  @spec push(Contract.t(), binary() | Script.chunk() | [binary() | Script.chunk()]) :: Contract.t()
  def push(%Contract{} = ctx, items) when is_list(items) do
    Enum.reduce(items, ctx, &push(&2, &1))
  end

  def push(%Contract{} = ctx, {:op, _} = chunk), do: Contract.script_push(ctx, chunk)
  def push(%Contract{} = ctx, {:data, _} = chunk), do: Contract.script_push(ctx, chunk)
  def push(%Contract{} = ctx, data) when is_binary(data), do: Contract.script_push(ctx, {:data, data})

  def push(%Contract{} = ctx, n) when is_integer(n) and n == 0,
    do: Contract.script_push(ctx, {:op, 0x00})

  def push(%Contract{} = ctx, n) when is_integer(n) and n == -1,
    do: Contract.script_push(ctx, {:op, 0x4F})

  def push(%Contract{} = ctx, n) when is_integer(n) and n >= 1 and n <= 16,
    do: Contract.script_push(ctx, {:op, 0x50 + n})

  def push(%Contract{} = ctx, n) when is_integer(n) do
    # Encode as ScriptNum
    Contract.script_push(ctx, {:data, BSV.Script.ScriptNum.encode_num(n)})
  end

  @doc "Iterate over an enumerable, applying a function that takes (element, contract)."
  @spec each(Contract.t(), Enum.t(), (Enum.element(), Contract.t() -> Contract.t())) :: Contract.t()
  def each(%Contract{} = ctx, enum, fun), do: Enum.reduce(enum, ctx, fun)

  @doc "Repeat `n` times, calling fun.(index, contract)."
  @spec repeat(Contract.t(), pos_integer(), (non_neg_integer(), Contract.t() -> Contract.t())) :: Contract.t()
  def repeat(%Contract{} = ctx, n, fun) when n > 0 do
    Enum.reduce(0..(n - 1), ctx, fun)
  end

  @doc "Reverse the top stack item of `length` bytes using script ops."
  @spec reverse(Contract.t(), pos_integer()) :: Contract.t()
  def reverse(%Contract{} = ctx, length) when length > 1 do
    ctx
    |> repeat(length - 1, fn _i, c -> c |> op_1() |> op_split() end)
    |> repeat(length - 1, fn _i, c -> c |> op_swap() |> op_cat() end)
  end

  @doc "Extract bytes from top stack item: start index for length bytes."
  @spec slice(Contract.t(), integer(), non_neg_integer()) :: Contract.t()
  def slice(%Contract{} = ctx, start, length) when start < 0 do
    ctx |> op_size() |> push(start * -1) |> op_sub() |> op_split() |> op_nip() |> slice(0, length)
  end

  def slice(%Contract{} = ctx, start, length) when start > 0 do
    ctx |> trim(start) |> slice(0, length)
  end

  def slice(%Contract{} = ctx, 0, length) do
    ctx |> push(length) |> op_split() |> op_drop()
  end

  @doc "Trim leading (positive) or trailing (negative) bytes from top stack item."
  @spec trim(Contract.t(), integer()) :: Contract.t()
  def trim(%Contract{} = ctx, n) when n > 0, do: ctx |> push(n) |> op_split() |> op_nip()
  def trim(%Contract{} = ctx, n) when n < 0, do: ctx |> op_size() |> push(n * -1) |> op_sub() |> op_split() |> op_drop()
  def trim(%Contract{} = ctx, 0), do: ctx

  @doc "Decode top stack item as unsigned integer (little-endian ScriptNum)."
  @spec decode_uint(Contract.t()) :: Contract.t()
  def decode_uint(%Contract{} = ctx) do
    ctx |> push(<<0>>) |> op_cat() |> op_bin2num()
  end

  # --- Auto-generated opcode helpers ---
  # For every known opcode, define a pipeline function.

  @opcodes_to_generate [
    {:op_0, 0x00}, {:op_false, 0x00},
    {:op_1negate, 0x4F},
    {:op_1, 0x51}, {:op_true, 0x51},
    {:op_2, 0x52}, {:op_3, 0x53}, {:op_4, 0x54}, {:op_5, 0x55},
    {:op_6, 0x56}, {:op_7, 0x57}, {:op_8, 0x58}, {:op_9, 0x59},
    {:op_10, 0x5A}, {:op_11, 0x5B}, {:op_12, 0x5C}, {:op_13, 0x5D},
    {:op_14, 0x5E}, {:op_15, 0x5F}, {:op_16, 0x60},
    {:op_nop, 0x61},
    {:op_if, 0x63}, {:op_notif, 0x64},
    {:op_else, 0x67}, {:op_endif, 0x68},
    {:op_verify, 0x69}, {:op_return, 0x6A},
    {:op_toaltstack, 0x6B}, {:op_fromaltstack, 0x6C},
    {:op_2drop, 0x6D}, {:op_2dup, 0x6E}, {:op_3dup, 0x6F},
    {:op_2over, 0x70}, {:op_2rot, 0x71}, {:op_2swap, 0x72},
    {:op_ifdup, 0x73}, {:op_depth, 0x74},
    {:op_drop, 0x75}, {:op_dup, 0x76}, {:op_nip, 0x77},
    {:op_over, 0x78}, {:op_pick, 0x79}, {:op_roll, 0x7A},
    {:op_rot, 0x7B}, {:op_swap, 0x7C}, {:op_tuck, 0x7D},
    {:op_cat, 0x7E}, {:op_split, 0x7F},
    {:op_num2bin, 0x80}, {:op_bin2num, 0x81}, {:op_size, 0x82},
    {:op_invert, 0x83}, {:op_and, 0x84}, {:op_or, 0x85}, {:op_xor, 0x86},
    {:op_equal, 0x87}, {:op_equalverify, 0x88},
    {:op_1add, 0x8B}, {:op_1sub, 0x8C},
    {:op_negate, 0x8F}, {:op_abs, 0x90},
    {:op_not, 0x91}, {:op_0notequal, 0x92},
    {:op_add, 0x93}, {:op_sub, 0x94}, {:op_mul, 0x95},
    {:op_div, 0x96}, {:op_mod, 0x97},
    {:op_lshift, 0x98}, {:op_rshift, 0x99},
    {:op_booland, 0x9A}, {:op_boolor, 0x9B},
    {:op_numequal, 0x9C}, {:op_numequalverify, 0x9D},
    {:op_numnotequal, 0x9E},
    {:op_lessthan, 0x9F}, {:op_greaterthan, 0xA0},
    {:op_lessthanorequal, 0xA1}, {:op_greaterthanorequal, 0xA2},
    {:op_min, 0xA3}, {:op_max, 0xA4}, {:op_within, 0xA5},
    {:op_ripemd160, 0xA6}, {:op_sha1, 0xA7}, {:op_sha256, 0xA8},
    {:op_hash160, 0xA9}, {:op_hash256, 0xAA},
    {:op_codeseparator, 0xAB},
    {:op_checksig, 0xAC}, {:op_checksigverify, 0xAD},
    {:op_checkmultisig, 0xAE}, {:op_checkmultisigverify, 0xAF}
  ]

  for {name, byte} <- @opcodes_to_generate do
    op_name = Opcodes.opcode_to_name(byte)

    @doc "Push `#{op_name}` onto the script."
    @spec unquote(name)(Contract.t()) :: Contract.t()
    def unquote(name)(%Contract{} = ctx) do
      Contract.script_push(ctx, {:op, unquote(byte)})
    end
  end

  # --- Flow control helpers with callbacks ---

  @doc "Wrap `handle_if` between OP_IF and OP_ENDIF."
  @spec op_if(Contract.t(), (Contract.t() -> Contract.t())) :: Contract.t()
  def op_if(%Contract{} = ctx, handle_if) when is_function(handle_if, 1) do
    ctx |> op_if() |> handle_if.() |> op_endif()
  end

  @doc "Wrap `handle_if`/`handle_else` between OP_IF, OP_ELSE, OP_ENDIF."
  @spec op_if(Contract.t(), (Contract.t() -> Contract.t()), (Contract.t() -> Contract.t())) :: Contract.t()
  def op_if(%Contract{} = ctx, handle_if, handle_else)
      when is_function(handle_if, 1) and is_function(handle_else, 1) do
    ctx |> op_if() |> handle_if.() |> op_else() |> handle_else.() |> op_endif()
  end

  @doc "Wrap `handle` between OP_NOTIF and OP_ENDIF."
  @spec op_notif(Contract.t(), (Contract.t() -> Contract.t())) :: Contract.t()
  def op_notif(%Contract{} = ctx, handle) when is_function(handle, 1) do
    ctx |> op_notif() |> handle.() |> op_endif()
  end

  @doc "Wrap `handle_if`/`handle_else` between OP_NOTIF, OP_ELSE, OP_ENDIF."
  @spec op_notif(Contract.t(), (Contract.t() -> Contract.t()), (Contract.t() -> Contract.t())) :: Contract.t()
  def op_notif(%Contract{} = ctx, handle_if, handle_else)
      when is_function(handle_if, 1) and is_function(handle_else, 1) do
    ctx |> op_notif() |> handle_if.() |> op_else() |> handle_else.() |> op_endif()
  end
end
