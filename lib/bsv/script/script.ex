defmodule BSV.Script do
  @moduledoc """
  Bitcoin Script type — a sequence of opcodes and data pushes.

  Scripts are used in transaction inputs (unlocking) and outputs (locking)
  to define spending conditions.
  """

  require BSV.Script.Opcodes
  alias BSV.Script.Opcodes

  @type chunk :: {:op, byte()} | {:data, binary()}
  @type t :: %__MODULE__{chunks: [chunk()]}

  defstruct chunks: []

  @doc "Create a new empty script."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc "Parse a binary into a Script struct."
  @spec from_binary(binary()) :: {:ok, t()} | {:error, term()}
  def from_binary(bin) when is_binary(bin) do
    case parse_chunks(bin, []) do
      {:ok, chunks} -> {:ok, %__MODULE__{chunks: Enum.reverse(chunks)}}
      {:error, _} = err -> err
    end
  end

  @doc "Parse a hex string into a Script."
  @spec from_hex(String.t()) :: {:ok, t()} | {:error, term()}
  def from_hex(hex) when is_binary(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> from_binary(bin)
      :error -> {:error, :invalid_hex}
    end
  end

  @doc "Parse a Bitcoin ASM string into a Script."
  @spec from_asm(String.t()) :: {:ok, t()} | {:error, term()}
  def from_asm(""), do: {:ok, new()}

  def from_asm(asm) when is_binary(asm) do
    tokens = String.split(asm, " ", trim: true)
    parse_asm_tokens(tokens, [])
  end

  @doc "Serialize a script to raw bytes."
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{chunks: chunks}) do
    Enum.reduce(chunks, <<>>, fn chunk, acc ->
      acc <> chunk_to_binary(chunk)
    end)
  end

  @doc "Serialize a script to a hex string."
  @spec to_hex(t()) :: String.t()
  def to_hex(%__MODULE__{} = script) do
    script |> to_binary() |> Base.encode16(case: :lower)
  end

  @doc "Convert a script to its ASM string representation."
  @spec to_asm(t()) :: String.t()
  def to_asm(%__MODULE__{chunks: chunks}) do
    chunks
    |> Enum.map(&chunk_to_asm/1)
    |> Enum.join(" ")
  end

  @doc "Build a P2PKH locking script from a 20-byte public key hash."
  @spec p2pkh_lock(<<_::160>>) :: t()
  def p2pkh_lock(<<pkh::binary-size(20)>>) do
    %__MODULE__{
      chunks: [
        {:op, Opcodes.op_dup()},
        {:op, Opcodes.op_hash160()},
        {:data, pkh},
        {:op, Opcodes.op_equalverify()},
        {:op, Opcodes.op_checksig()}
      ]
    }
  end

  @doc "Build a P2PKH unlocking script from a signature and public key."
  @spec p2pkh_unlock(binary(), binary()) :: t()
  def p2pkh_unlock(signature, pubkey) when is_binary(signature) and is_binary(pubkey) do
    %__MODULE__{chunks: [{:data, signature}, {:data, pubkey}]}
  end

  @doc "Build an OP_RETURN data script (OP_FALSE OP_RETURN <data>...)."
  @spec op_return([binary()]) :: t()
  def op_return(data_list) when is_list(data_list) do
    data_chunks = Enum.map(data_list, &{:data, &1})
    %__MODULE__{chunks: [{:op, Opcodes.op_0()}, {:op, Opcodes.op_return()} | data_chunks]}
  end

  @doc "Check if a script is P2PKH."
  @spec is_p2pkh?(t()) :: boolean()
  def is_p2pkh?(%__MODULE__{chunks: chunks}) do
    match?(
      [
        {:op, 0x76},
        {:op, 0xA9},
        {:data, <<_::binary-size(20)>>},
        {:op, 0x88},
        {:op, 0xAC}
      ],
      chunks
    )
  end

  @doc "Check if a script is OP_RETURN data."
  @spec is_op_return?(t()) :: boolean()
  def is_op_return?(%__MODULE__{chunks: [{:op, 0x6A} | _]}), do: true
  def is_op_return?(%__MODULE__{chunks: [{:op, 0x00}, {:op, 0x6A} | _]}), do: true
  def is_op_return?(%__MODULE__{chunks: [{:data, <<>>}, {:op, 0x6A} | _]}), do: true
  def is_op_return?(_), do: false

  @doc "Check if a script is P2SH (OP_HASH160 <20 bytes> OP_EQUAL)."
  @spec is_p2sh?(t()) :: boolean()
  def is_p2sh?(%__MODULE__{chunks: chunks}) do
    match?(
      [{:op, 0xA9}, {:data, <<_::binary-size(20)>>}, {:op, 0x87}],
      chunks
    )
  end

  @doc "Extract the public key hash from a P2PKH script."
  @spec get_pubkey_hash(t()) :: {:ok, <<_::160>>} | :error
  def get_pubkey_hash(%__MODULE__{chunks: chunks}) do
    case chunks do
      [{:op, 0x76}, {:op, 0xA9}, {:data, <<pkh::binary-size(20)>>}, {:op, 0x88}, {:op, 0xAC}] ->
        {:ok, pkh}

      _ ->
        :error
    end
  end

  # ---- Chunk parsing ----

  defp parse_chunks(<<>>, acc), do: {:ok, acc}

  # OP_0 → empty data push
  defp parse_chunks(<<0x00, rest::binary>>, acc) do
    parse_chunks(rest, [{:data, <<>>} | acc])
  end

  # Direct data push: 0x01..0x4B
  defp parse_chunks(<<op, rest::binary>>, acc) when op >= 0x01 and op <= 0x4B do
    case rest do
      <<data::binary-size(op), rest2::binary>> ->
        parse_chunks(rest2, [{:data, data} | acc])

      _ ->
        {:error, :data_too_small}
    end
  end

  # OP_PUSHDATA1
  defp parse_chunks(<<0x4C, rest::binary>>, acc) do
    case rest do
      <<len, data::binary-size(len), rest2::binary>> ->
        parse_chunks(rest2, [{:data, data} | acc])

      _ ->
        {:error, :data_too_small}
    end
  end

  # OP_PUSHDATA2
  defp parse_chunks(<<0x4D, rest::binary>>, acc) do
    case rest do
      <<len::little-16, data::binary-size(len), rest2::binary>> ->
        parse_chunks(rest2, [{:data, data} | acc])

      _ ->
        {:error, :data_too_small}
    end
  end

  # OP_PUSHDATA4
  defp parse_chunks(<<0x4E, rest::binary>>, acc) do
    case rest do
      <<len::little-32, data::binary-size(len), rest2::binary>> ->
        parse_chunks(rest2, [{:data, data} | acc])

      _ ->
        {:error, :data_too_small}
    end
  end

  # Any other opcode
  defp parse_chunks(<<op, rest::binary>>, acc) do
    parse_chunks(rest, [{:op, op} | acc])
  end

  # ---- Chunk serialization ----

  defp chunk_to_binary({:data, <<>>}), do: <<0x00>>

  defp chunk_to_binary({:data, data}) when byte_size(data) <= 75 do
    <<byte_size(data)::8, data::binary>>
  end

  defp chunk_to_binary({:data, data}) when byte_size(data) <= 0xFF do
    <<0x4C, byte_size(data)::8, data::binary>>
  end

  defp chunk_to_binary({:data, data}) when byte_size(data) <= 0xFFFF do
    <<0x4D, byte_size(data)::little-16, data::binary>>
  end

  defp chunk_to_binary({:data, data}) do
    <<0x4E, byte_size(data)::little-32, data::binary>>
  end

  defp chunk_to_binary({:op, byte}), do: <<byte>>

  # ---- Chunk to ASM ----

  defp chunk_to_asm({:data, <<>>}), do: "OP_0"

  defp chunk_to_asm({:data, data}) do
    Base.encode16(data, case: :lower)
  end

  defp chunk_to_asm({:op, byte}) do
    Opcodes.opcode_to_name(byte)
  end

  # ---- ASM parsing ----

  defp parse_asm_tokens([], acc), do: {:ok, %__MODULE__{chunks: Enum.reverse(acc)}}

  defp parse_asm_tokens([token | rest], acc) do
    case Opcodes.name_to_opcode(token) do
      {:ok, op} ->
        # OP_0 is data push of empty
        chunk = if op == 0x00, do: {:data, <<>>}, else: {:op, op}
        parse_asm_tokens(rest, [chunk | acc])

      :error ->
        # Try as hex data
        case Base.decode16(token, case: :mixed) do
          {:ok, data} -> parse_asm_tokens(rest, [{:data, data} | acc])
          :error -> {:error, {:invalid_asm_token, token}}
        end
    end
  end
end
