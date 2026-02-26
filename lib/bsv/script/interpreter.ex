defmodule BSV.Script.Interpreter do
  @moduledoc """
  Full Bitcoin script interpreter.

  Executes unlocking and locking scripts to verify transaction inputs.
  Supports all standard opcodes including stack, arithmetic, crypto,
  comparison, flow control, and splice operations.

  ## Limitations

  OP_CHECKLOCKTIMEVERIFY (0xB1) and OP_CHECKSEQUENCEVERIFY (0xB2) are currently
  treated as NOPs and are not fully validated against transaction lock_time or
  input sequence numbers.
  """

  import Bitwise

  alias BSV.Script
  alias BSV.Script.ScriptNum
  require BSV.Script.Opcodes

  @type flag ::
          :utxo_after_genesis
          | :verify_minimal_data
          | :verify_clean_stack
          | :enable_sighash_forkid

  @type opts :: [
          flags: [flag()],
          sighash_fn: (Script.t(), non_neg_integer(), non_neg_integer() ->
                         {:ok, binary()} | {:error, term()})
        ]

  defmodule State do
    @moduledoc false
    @type t :: %__MODULE__{}
    defstruct dstack: [],
              astack: [],
              cond_stack: [],
              flags: [],
              num_ops: 0,
              chunk_index: 0,
              last_code_separator: nil,
              sighash_fn: nil,
              after_genesis: false,
              max_ops: 500_000_000,
              max_script_num_len: 750_000,
              max_element_size: 520,
              max_stack_size: 1_000
  end

  @doc """
  Verify an unlocking script against a locking script.

  Returns `:ok` on success or `{:error, reason}` on failure.

  ## Options

    * `:flags` - List of verification flag atoms
    * `:sighash_fn` - Function for OP_CHECKSIG sighash computation

  ## Examples

      iex> {:ok, lock} = BSV.Script.from_asm("OP_1")
      iex> BSV.Script.Interpreter.verify(%BSV.Script{}, lock)
      :ok
  """
  @spec verify(Script.t(), Script.t(), opts()) :: :ok | {:error, term()}
  def verify(%Script{} = unlock, %Script{} = lock, opts \\ []) do
    flags = Keyword.get(opts, :flags, [])
    after_genesis = :utxo_after_genesis in flags

    state = %State{
      flags: flags,
      sighash_fn: Keyword.get(opts, :sighash_fn),
      after_genesis: after_genesis,
      max_ops: if(after_genesis, do: 500_000_000, else: 500),
      max_script_num_len: if(after_genesis, do: 750_000, else: 4),
      max_element_size: if(after_genesis, do: 4_294_967_295, else: 520),
      max_stack_size: if(after_genesis, do: 4_294_967_295, else: 1_000)
    }

    # Execute unlocking script
    with {:ok, state} <- execute_chunks(unlock.chunks, state),
         # Reject unbalanced conditionals leaking from unlock into lock script
         true <- state.cond_stack == [] || {:error, :unbalanced_conditional_in_unlock},
         # Clear alt stack between scripts, reset counters
         state = %{state | astack: [], num_ops: 0, chunk_index: 0, last_code_separator: nil},
         # Execute locking script
         {:ok, state} <- execute_chunks(lock.chunks, state) do
      if state.cond_stack != [] do
        {:error, :unbalanced_conditional}
      else
        check_final_stack(state)
      end
    end
  end

  # ---- Execute a list of chunks ----

  defp execute_chunks([], state), do: {:ok, state}

  defp execute_chunks([chunk | rest], state) do
    case execute_chunk(chunk, state) do
      {:ok, state} ->
        case check_stack_size(state) do
          {:ok, state} ->
            execute_chunks(rest, %{state | chunk_index: state.chunk_index + 1})
          {:error, _} = err -> err
        end

      {:error, _} = err ->
        err
    end
  end

  # ---- Execute a single chunk ----

  defp execute_chunk(chunk, %State{cond_stack: cond_stack} = state) do
    executing = executing?(cond_stack)

    case chunk do
      {:data, data} ->
        if executing do
          {:ok, push(state, data)}
        else
          {:ok, state}
        end

      {:op, op} ->
        # Conditional ops are always processed
        if executing or conditional_op?(op) do
          execute_op(op, state)
        else
          {:ok, state}
        end
    end
  end

  defp executing?([]), do: true
  defp executing?(cond_stack), do: Enum.all?(cond_stack, & &1)

  # OP_IF
  defp conditional_op?(0x63), do: true
  # OP_NOTIF
  defp conditional_op?(0x64), do: true
  # OP_ELSE
  defp conditional_op?(0x67), do: true
  # OP_ENDIF
  defp conditional_op?(0x68), do: true
  defp conditional_op?(_), do: false

  # ---- Stack helpers ----

  defp push(%State{dstack: stack} = state, val) do
    %{state | dstack: [val | stack]}
  end

  defp check_stack_size(%State{dstack: d, astack: a, max_stack_size: max} = state) do
    if length(d) + length(a) > max do
      {:error, :stack_size_exceeded}
    else
      {:ok, state}
    end
  end

  defp pop(%State{dstack: [top | rest]} = state), do: {:ok, top, %{state | dstack: rest}}
  defp pop(%State{dstack: []}), do: {:error, :stack_underflow}

  defp peek(%State{dstack: [top | _]}), do: {:ok, top}
  defp peek(%State{dstack: []}), do: {:error, :stack_underflow}

  defp pop_num(state) do
    with {:ok, val, state} <- pop(state) do
      {:ok, ScriptNum.decode_num(val), state}
    end
  end

  defp pop_num2(state) do
    with {:ok, b_bin, state} <- pop(state),
         {:ok, a_bin, state} <- pop(state) do
      {:ok, ScriptNum.decode_num(a_bin), ScriptNum.decode_num(b_bin), state}
    end
  end

  defp push_num(state, n), do: push(state, ScriptNum.encode_num(n))
  defp push_bool(state, true), do: push(state, <<1>>)
  defp push_bool(state, false), do: push(state, <<>>)

  defp is_truthy(<<>>), do: false

  defp is_truthy(bin) when is_binary(bin) do
    # False if all bytes are zero, or if all bytes are zero except the sign bit
    # of the last byte (negative zero). E.g. <<0x80>>, <<0x00, 0x80>>, etc.
    bytes = :binary.bin_to_list(bin)
    {init, [last]} = Enum.split(bytes, -1)
    not (Enum.all?(init, &(&1 == 0)) and (last == 0 or last == 0x80))
  end

  defp count_op(%State{num_ops: n, max_ops: max}) when n + 1 > max, do: {:error, :too_many_ops}
  defp count_op(%State{num_ops: n} = state), do: {:ok, %{state | num_ops: n + 1}}

  # ---- Opcode dispatch ----

  # Count non-push ops
  defp execute_op(op, state) when op > 0x60 do
    with {:ok, state} <- count_op(state) do
      do_execute_op(op, state)
    end
  end

  defp execute_op(op, state), do: do_execute_op(op, state)

  # -- Flow control --

  # OP_NOP
  defp do_execute_op(0x61, state), do: {:ok, state}

  # OP_IF
  defp do_execute_op(0x63, state) do
    if executing?(state.cond_stack) do
      with {:ok, val, state} <- pop(state) do
        {:ok, %{state | cond_stack: [is_truthy(val) | state.cond_stack]}}
      end
    else
      {:ok, %{state | cond_stack: [false | state.cond_stack]}}
    end
  end

  # OP_NOTIF
  defp do_execute_op(0x64, state) do
    if executing?(state.cond_stack) do
      with {:ok, val, state} <- pop(state) do
        {:ok, %{state | cond_stack: [not is_truthy(val) | state.cond_stack]}}
      end
    else
      {:ok, %{state | cond_stack: [false | state.cond_stack]}}
    end
  end

  # OP_ELSE
  defp do_execute_op(0x67, %State{cond_stack: []} = _state) do
    {:error, :unbalanced_conditional}
  end

  defp do_execute_op(0x67, %State{cond_stack: [top | rest]} = state) do
    {:ok, %{state | cond_stack: [not top | rest]}}
  end

  # OP_ENDIF
  defp do_execute_op(0x68, %State{cond_stack: []} = _state) do
    {:error, :unbalanced_conditional}
  end

  defp do_execute_op(0x68, %State{cond_stack: [_ | rest]} = state) do
    {:ok, %{state | cond_stack: rest}}
  end

  # OP_VERIFY
  defp do_execute_op(0x69, state) do
    with {:ok, val, state} <- pop(state) do
      if is_truthy(val), do: {:ok, state}, else: {:error, :verify_failed}
    end
  end

  # OP_RETURN
  defp do_execute_op(0x6A, _state), do: {:error, :op_return}

  # -- OP_1NEGATE --
  defp do_execute_op(0x4F, state), do: {:ok, push_num(state, -1)}

  # -- OP_1 through OP_16 --
  defp do_execute_op(op, state) when op >= 0x51 and op <= 0x60 do
    {:ok, push(state, <<op - 0x50>>)}
  end

  # -- Stack ops --

  # OP_TOALTSTACK
  defp do_execute_op(0x6B, state) do
    with {:ok, val, state} <- pop(state) do
      {:ok, %{state | astack: [val | state.astack]}}
    end
  end

  # OP_FROMALTSTACK
  defp do_execute_op(0x6C, %State{astack: [val | rest]} = state) do
    {:ok, push(%{state | astack: rest}, val)}
  end

  defp do_execute_op(0x6C, _state), do: {:error, :alt_stack_underflow}

  # OP_2DROP
  defp do_execute_op(0x6D, state) do
    with {:ok, _, state} <- pop(state),
         {:ok, _, state} <- pop(state) do
      {:ok, state}
    end
  end

  # OP_2DUP
  defp do_execute_op(0x6E, %State{dstack: [a, b | _]} = state) do
    {:ok, %{state | dstack: [a, b | state.dstack]}}
  end

  defp do_execute_op(0x6E, _state), do: {:error, :stack_underflow}

  # OP_3DUP
  defp do_execute_op(0x6F, %State{dstack: [a, b, c | _]} = state) do
    {:ok, %{state | dstack: [a, b, c | state.dstack]}}
  end

  defp do_execute_op(0x6F, _state), do: {:error, :stack_underflow}

  # OP_2OVER
  defp do_execute_op(0x70, %State{dstack: [_, _, c, d | _]} = state) do
    {:ok, %{state | dstack: [c, d | state.dstack]}}
  end

  defp do_execute_op(0x70, _state), do: {:error, :stack_underflow}

  # OP_2ROT
  defp do_execute_op(0x71, %State{dstack: [a, b, c, d, e, f | rest]} = state) do
    {:ok, %{state | dstack: [e, f, a, b, c, d | rest]}}
  end

  defp do_execute_op(0x71, _state), do: {:error, :stack_underflow}

  # OP_2SWAP
  defp do_execute_op(0x72, %State{dstack: [a, b, c, d | rest]} = state) do
    {:ok, %{state | dstack: [c, d, a, b | rest]}}
  end

  defp do_execute_op(0x72, _state), do: {:error, :stack_underflow}

  # OP_IFDUP
  defp do_execute_op(0x73, state) do
    with {:ok, val} <- peek(state) do
      if is_truthy(val),
        do: {:ok, push(state, val)},
        else: {:ok, state}
    end
  end

  # OP_DEPTH
  defp do_execute_op(0x74, %State{dstack: stack} = state) do
    {:ok, push_num(state, length(stack))}
  end

  # OP_DROP
  defp do_execute_op(0x75, state) do
    with {:ok, _, state} <- pop(state), do: {:ok, state}
  end

  # OP_DUP
  defp do_execute_op(0x76, state) do
    with {:ok, val} <- peek(state), do: {:ok, push(state, val)}
  end

  # OP_NIP
  defp do_execute_op(0x77, %State{dstack: [a, _ | rest]} = state) do
    {:ok, %{state | dstack: [a | rest]}}
  end

  defp do_execute_op(0x77, _state), do: {:error, :stack_underflow}

  # OP_OVER
  defp do_execute_op(0x78, %State{dstack: [_, b | _]} = state) do
    {:ok, push(state, b)}
  end

  defp do_execute_op(0x78, _state), do: {:error, :stack_underflow}

  # OP_PICK
  defp do_execute_op(0x79, state) do
    with {:ok, n, state} <- pop_num(state) do
      if n < 0 or n >= length(state.dstack) do
        {:error, :stack_underflow}
      else
        {:ok, push(state, Enum.at(state.dstack, n))}
      end
    end
  end

  # OP_ROLL
  defp do_execute_op(0x7A, state) do
    with {:ok, n, state} <- pop_num(state) do
      if n < 0 or n >= length(state.dstack) do
        {:error, :stack_underflow}
      else
        val = Enum.at(state.dstack, n)
        stack = List.delete_at(state.dstack, n)
        {:ok, %{state | dstack: [val | stack]}}
      end
    end
  end

  # OP_ROT
  defp do_execute_op(0x7B, %State{dstack: [a, b, c | rest]} = state) do
    {:ok, %{state | dstack: [c, a, b | rest]}}
  end

  defp do_execute_op(0x7B, _state), do: {:error, :stack_underflow}

  # OP_SWAP
  defp do_execute_op(0x7C, %State{dstack: [a, b | rest]} = state) do
    {:ok, %{state | dstack: [b, a | rest]}}
  end

  defp do_execute_op(0x7C, _state), do: {:error, :stack_underflow}

  # OP_TUCK
  defp do_execute_op(0x7D, %State{dstack: [a, b | rest]} = state) do
    {:ok, %{state | dstack: [a, b, a | rest]}}
  end

  defp do_execute_op(0x7D, _state), do: {:error, :stack_underflow}

  # -- Splice ops --

  # OP_CAT
  defp do_execute_op(0x7E, state) do
    with {:ok, b, state} <- pop(state),
         {:ok, a, state} <- pop(state) do
      result = a <> b

      if byte_size(result) > state.max_element_size do
        {:error, :element_size_exceeded}
      else
        {:ok, push(state, result)}
      end
    end
  end

  # OP_SPLIT
  defp do_execute_op(0x7F, state) do
    with {:ok, n, state} <- pop_num(state),
         {:ok, data, state} <- pop(state) do
      if n < 0 or n > byte_size(data) do
        {:error, :invalid_split_range}
      else
        <<left::binary-size(n), right::binary>> = data
        {:ok, push(push(state, left), right)}
      end
    end
  end

  # OP_NUM2BIN
  defp do_execute_op(0x80, state) do
    with {:ok, size, state} <- pop_num(state),
         {:ok, val, state} <- pop(state) do
      if size < 0 do
        {:error, :invalid_size}
      else
        num = ScriptNum.decode_num(val)
        encoded = ScriptNum.encode_num(num)
        padded = pad_num_to_size(encoded, size, num < 0)
        {:ok, push(state, padded)}
      end
    end
  end

  # OP_BIN2NUM
  defp do_execute_op(0x81, state) do
    with {:ok, val, state} <- pop(state) do
      num = ScriptNum.decode_num(val)
      {:ok, push(state, ScriptNum.encode_num(num))}
    end
  end

  # OP_SIZE
  defp do_execute_op(0x82, state) do
    with {:ok, val} <- peek(state) do
      {:ok, push_num(state, byte_size(val))}
    end
  end

  # -- Bitwise --

  # OP_INVERT
  defp do_execute_op(0x83, state) do
    with {:ok, val, state} <- pop(state) do
      inverted = for <<b <- val>>, into: <<>>, do: <<Bitwise.bxor(b, 0xFF)>>
      {:ok, push(state, inverted)}
    end
  end

  # OP_AND
  defp do_execute_op(0x84, state), do: bitwise_op(state, &Bitwise.band/2)
  # OP_OR
  defp do_execute_op(0x85, state), do: bitwise_op(state, &Bitwise.bor/2)
  # OP_XOR
  defp do_execute_op(0x86, state), do: bitwise_op(state, &Bitwise.bxor/2)

  # OP_EQUAL
  defp do_execute_op(0x87, state) do
    with {:ok, b, state} <- pop(state),
         {:ok, a, state} <- pop(state) do
      {:ok, push_bool(state, a == b)}
    end
  end

  # OP_EQUALVERIFY
  defp do_execute_op(0x88, state) do
    with {:ok, b, state} <- pop(state),
         {:ok, a, state} <- pop(state) do
      if a == b, do: {:ok, state}, else: {:error, :equalverify_failed}
    end
  end

  # -- Arithmetic --

  # OP_1ADD
  defp do_execute_op(0x8B, state), do: unary_num_op(state, &(&1 + 1))
  # OP_1SUB
  defp do_execute_op(0x8C, state), do: unary_num_op(state, &(&1 - 1))
  # OP_NEGATE
  defp do_execute_op(0x8F, state), do: unary_num_op(state, &(-&1))
  # OP_ABS
  defp do_execute_op(0x90, state), do: unary_num_op(state, &abs/1)

  # OP_NOT
  defp do_execute_op(0x91, state) do
    with {:ok, n, state} <- pop_num(state) do
      {:ok, push_bool(state, n == 0)}
    end
  end

  # OP_0NOTEQUAL
  defp do_execute_op(0x92, state) do
    with {:ok, n, state} <- pop_num(state) do
      {:ok, push_bool(state, n != 0)}
    end
  end

  # OP_ADD
  defp do_execute_op(0x93, state), do: binary_num_op(state, &(&1 + &2))
  # OP_SUB
  defp do_execute_op(0x94, state), do: binary_num_op(state, &(&1 - &2))
  # OP_MUL
  defp do_execute_op(0x95, state), do: binary_num_op(state, &(&1 * &2))

  # OP_DIV
  defp do_execute_op(0x96, state) do
    with {:ok, a, b, state} <- pop_num2(state) do
      if b == 0, do: {:error, :divide_by_zero}, else: {:ok, push_num(state, div(a, b))}
    end
  end

  # OP_MOD
  defp do_execute_op(0x97, state) do
    with {:ok, a, b, state} <- pop_num2(state) do
      if b == 0, do: {:error, :divide_by_zero}, else: {:ok, push_num(state, rem(a, b))}
    end
  end

  # OP_LSHIFT
  defp do_execute_op(0x98, state) do
    with {:ok, n, state} <- pop_num(state),
         {:ok, val, state} <- pop(state) do
      if n < 0, do: {:error, :invalid_shift}, else: {:ok, push(state, shift_left(val, n))}
    end
  end

  # OP_RSHIFT
  defp do_execute_op(0x99, state) do
    with {:ok, n, state} <- pop_num(state),
         {:ok, val, state} <- pop(state) do
      if n < 0, do: {:error, :invalid_shift}, else: {:ok, push(state, shift_right(val, n))}
    end
  end

  # OP_BOOLAND
  defp do_execute_op(0x9A, state) do
    with {:ok, a, b, state} <- pop_num2(state) do
      {:ok, push_bool(state, a != 0 and b != 0)}
    end
  end

  # OP_BOOLOR
  defp do_execute_op(0x9B, state) do
    with {:ok, a, b, state} <- pop_num2(state) do
      {:ok, push_bool(state, a != 0 or b != 0)}
    end
  end

  # OP_NUMEQUAL
  defp do_execute_op(0x9C, state), do: bool_binop(state, &==/2)
  # OP_NUMEQUALVERIFY
  defp do_execute_op(0x9D, state) do
    with {:ok, a, b, state} <- pop_num2(state) do
      if a == b, do: {:ok, state}, else: {:error, :numequalverify_failed}
    end
  end

  # OP_NUMNOTEQUAL
  defp do_execute_op(0x9E, state), do: bool_binop(state, &!=/2)
  # OP_LESSTHAN
  defp do_execute_op(0x9F, state), do: bool_binop(state, &</2)
  # OP_GREATERTHAN
  defp do_execute_op(0xA0, state), do: bool_binop(state, &>/2)
  # OP_LESSTHANOREQUAL
  defp do_execute_op(0xA1, state), do: bool_binop(state, &<=/2)
  # OP_GREATERTHANOREQUAL
  defp do_execute_op(0xA2, state), do: bool_binop(state, &>=/2)

  # OP_MIN
  defp do_execute_op(0xA3, state), do: binary_num_op(state, &min/2)
  # OP_MAX
  defp do_execute_op(0xA4, state), do: binary_num_op(state, &max/2)

  # OP_WITHIN
  defp do_execute_op(0xA5, state) do
    with {:ok, max_bin, state} <- pop(state),
         {:ok, min_bin, state} <- pop(state),
         {:ok, x_bin, state} <- pop(state) do
      x = ScriptNum.decode_num(x_bin)
      mn = ScriptNum.decode_num(min_bin)
      mx = ScriptNum.decode_num(max_bin)
      {:ok, push_bool(state, x >= mn and x < mx)}
    end
  end

  # -- Crypto --

  # OP_RIPEMD160
  defp do_execute_op(0xA6, state), do: hash_op(state, :ripemd160)
  # OP_SHA1
  defp do_execute_op(0xA7, state), do: hash_op(state, :sha)
  # OP_SHA256
  defp do_execute_op(0xA8, state), do: hash_op(state, :sha256)

  # OP_HASH160
  defp do_execute_op(0xA9, state) do
    with {:ok, val, state} <- pop(state) do
      {:ok, push(state, BSV.Crypto.hash160(val))}
    end
  end

  # OP_HASH256
  defp do_execute_op(0xAA, state) do
    with {:ok, val, state} <- pop(state) do
      {:ok, push(state, BSV.Crypto.sha256d(val))}
    end
  end

  # OP_CODESEPARATOR — record position for subsequent OP_CHECKSIG subscript
  defp do_execute_op(0xAB, state) do
    {:ok, %{state | last_code_separator: state.chunk_index}}
  end

  # OP_CHECKSIG
  defp do_execute_op(0xAC, state) do
    with {:ok, pubkey, state} <- pop(state),
         {:ok, sig, state} <- pop(state) do
      case state.sighash_fn do
        nil ->
          {:error, :no_sighash_fn}

        sighash_fn ->
          if byte_size(sig) == 0 do
            {:ok, push_bool(state, false)}
          else
            sighash_type = :binary.last(sig)
            sig_body = binary_part(sig, 0, byte_size(sig) - 1)

            case sighash_fn.(sig_body, pubkey, sighash_type) do
              {:ok, true} -> {:ok, push_bool(state, true)}
              {:ok, false} -> {:ok, push_bool(state, false)}
              {:error, _} = err -> err
            end
          end
      end
    end
  end

  # OP_CHECKSIGVERIFY
  defp do_execute_op(0xAD, state) do
    with {:ok, state} <- do_execute_op(0xAC, state),
         {:ok, val, state} <- pop(state) do
      if is_truthy(val), do: {:ok, state}, else: {:error, :checksigverify_failed}
    end
  end

  # OP_CHECKMULTISIG
  defp do_execute_op(0xAE, state) do
    with {:ok, nkeys, state} <- pop_num(state) do
      if nkeys < 0 or nkeys > 20 do
        {:error, :invalid_pubkey_count}
      else
        # HIGH-06: Add nkeys to op counter per consensus
        state = %{state | num_ops: state.num_ops + nkeys}

        if state.num_ops > state.max_ops do
          {:error, :too_many_ops}
        else
          with {:ok, keys, state} <- pop_n(state, nkeys),
               {:ok, nsigs, state} <- pop_num(state) do
            if nsigs < 0 or nsigs > nkeys do
              {:error, :invalid_sig_count}
            else
              with {:ok, sigs, state} <- pop_n(state, nsigs),
                   # Pop the dummy element (protocol bug)
                   {:ok, _dummy, state} <- pop(state) do
                case state.sighash_fn do
                  nil ->
                    {:error, :no_sighash_fn}

                  sighash_fn ->
                    success = verify_multisig(sigs, keys, sighash_fn)
                    {:ok, push_bool(state, success)}
                end
              end
            end
          end
        end
      end
    end
  end

  # OP_CHECKMULTISIGVERIFY
  defp do_execute_op(0xAF, state) do
    with {:ok, state} <- do_execute_op(0xAE, state),
         {:ok, val, state} <- pop(state) do
      if is_truthy(val), do: {:ok, state}, else: {:error, :checkmultisigverify_failed}
    end
  end

  # -- NOP opcodes --
  defp do_execute_op(op, state) when op >= 0xB0 and op <= 0xB9, do: {:ok, state}

  # Unknown/invalid
  defp do_execute_op(op, _state), do: {:error, {:unknown_opcode, op}}

  # ---- Helpers ----

  defp check_final_stack(%State{dstack: []}) do
    {:error, :empty_stack}
  end

  defp check_final_stack(%State{dstack: [top | _]}) do
    if is_truthy(top), do: :ok, else: {:error, :eval_false}
  end

  defp unary_num_op(state, fun) do
    with {:ok, n, state} <- pop_num(state) do
      {:ok, push_num(state, fun.(n))}
    end
  end

  defp binary_num_op(state, fun) do
    with {:ok, a, b, state} <- pop_num2(state) do
      {:ok, push_num(state, fun.(a, b))}
    end
  end

  defp bool_binop(state, fun) do
    with {:ok, a, b, state} <- pop_num2(state) do
      {:ok, push_bool(state, fun.(a, b))}
    end
  end

  defp hash_op(state, algo) do
    with {:ok, val, state} <- pop(state) do
      {:ok, push(state, :crypto.hash(algo, val))}
    end
  end

  defp bitwise_op(state, fun) do
    with {:ok, b, state} <- pop(state),
         {:ok, a, state} <- pop(state) do
      if byte_size(a) != byte_size(b) do
        {:error, :invalid_operand_size}
      else
        result =
          Enum.zip(:binary.bin_to_list(a), :binary.bin_to_list(b))
          |> Enum.map(fn {x, y} -> fun.(x, y) end)
          |> :binary.list_to_bin()

        {:ok, push(state, result)}
      end
    end
  end

  defp shift_left(bin, 0), do: bin

  defp shift_left(bin, n) when is_binary(bin) and n > 0 do
    bits = byte_size(bin) * 8
    num = :binary.decode_unsigned(bin, :big)
    shifted = Bitwise.band(Bitwise.bsl(num, n), (1 <<< bits) - 1)
    <<shifted::unsigned-big-size(bits)>>
  end

  defp shift_right(bin, 0), do: bin

  defp shift_right(bin, n) when is_binary(bin) and n > 0 do
    bits = byte_size(bin) * 8
    num = :binary.decode_unsigned(bin, :big)
    shifted = Bitwise.bsr(num, n)
    <<shifted::unsigned-big-size(bits)>>
  end

  defp pad_num_to_size(bin, size, _negative) when byte_size(bin) >= size, do: bin

  defp pad_num_to_size(<<>>, size, _negative) do
    :binary.copy(<<0>>, size)
  end

  defp pad_num_to_size(bin, size, negative) do
    padding = size - byte_size(bin)

    if negative do
      # Remove sign from current last byte, pad with zeros, add sign on new last
      bytes = :binary.bin_to_list(bin)
      last = List.last(bytes)
      init = :lists.sublist(bytes, length(bytes) - 1) ++ [last &&& 0x7F]
      padded = init ++ List.duplicate(0, padding - 1) ++ [0x80]
      :binary.list_to_bin(padded)
    else
      bin <> :binary.copy(<<0>>, padding)
    end
  end

  defp pop_n(state, 0), do: {:ok, [], state}

  defp pop_n(state, n) when n > 0 do
    with {:ok, val, state} <- pop(state),
         {:ok, rest, state} <- pop_n(state, n - 1) do
      {:ok, [val | rest], state}
    end
  end

  defp verify_multisig([], _keys, _fn), do: true
  defp verify_multisig(_sigs, [], _fn), do: false

  defp verify_multisig([sig | rest_sigs] = sigs, [key | rest_keys], sighash_fn) do
    if byte_size(sig) == 0 do
      false
    else
      sighash_type = :binary.last(sig)
      sig_body = binary_part(sig, 0, byte_size(sig) - 1)

      case sighash_fn.(sig_body, key, sighash_type) do
        {:ok, true} -> verify_multisig(rest_sigs, rest_keys, sighash_fn)
        _ -> verify_multisig(sigs, rest_keys, sighash_fn)
      end
    end
  end
end
