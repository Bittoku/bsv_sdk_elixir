defmodule BSV.Transaction.P2MPKH do
  @moduledoc """
  Pay-to-Multiple-Public-Key-Hash (P2MPKH) signing template.

  Extends P2PKH to support m-of-n multisig ownership. The locking script
  stores only the HASH160 of a raw multisig script (the "MPKH") — the full
  multisig script remains hidden until spending.

  ## MultisigScript

  A multisig script is represented as a map:

      %{threshold: 2, public_keys: [pk1, pk2, pk3]}

  where each public key is a 33-byte compressed SEC1 binary.

  ## Standalone locking script (bare multisig)

      OP_m <pk1> <pk2> … <pkN> OP_n OP_CHECKMULTISIG

  ## Standalone unlocking script

      OP_0 <sig1> <sig2> … <sigM>

  ## STAS unlocking script (P2MPKH mode)

      <sig1> <sig2> … <sigM> <serialized_multisig_script>

  STAS handles HASH160 verification and OP_CHECKMULTISIG internally.
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Crypto, Script, PrivateKey}
  alias BSV.Script.Opcodes
  alias BSV.Transaction.Sighash

  require Opcodes

  @max_keys 16

  # -- MultisigScript helpers --

  @type multisig_script :: %{
          threshold: pos_integer(),
          public_keys: [binary()]
        }

  @doc """
  Create a new multisig script map.

  ## Arguments
  - `threshold` — minimum signatures required (m)
  - `public_keys` — list of 33-byte compressed public keys

  ## Returns
  `{:ok, multisig_script()}` or `{:error, reason}`
  """
  @spec new_multisig(pos_integer(), [binary()]) :: {:ok, multisig_script()} | {:error, term()}
  def new_multisig(threshold, public_keys) when is_integer(threshold) and is_list(public_keys) do
    n = length(public_keys)

    cond do
      n < 1 ->
        {:error, :no_public_keys}

      n > @max_keys ->
        {:error, {:too_many_keys, n}}

      threshold < 1 ->
        {:error, :threshold_too_low}

      threshold > n ->
        {:error, {:threshold_exceeds_keys, threshold, n}}

      not Enum.all?(public_keys, &(is_binary(&1) and byte_size(&1) == 33)) ->
        {:error, :invalid_public_key_size}

      true ->
        {:ok, %{threshold: threshold, public_keys: public_keys}}
    end
  end

  # OP_1..OP_16 = 0x51..0x60; base = 0x50 so OP_N = base + N
  @op_base 0x50

  @doc """
  Serialize a multisig script to raw bytes.

  Produces: `OP_m <pk1> <pk2> … <pkN> OP_n OP_CHECKMULTISIG`
  """
  @spec to_script_bytes(multisig_script()) :: binary()
  def to_script_bytes(%{threshold: m, public_keys: pks}) do
    n = length(pks)
    op_m = @op_base + m
    op_n = @op_base + n

    key_pushes =
      Enum.reduce(pks, <<>>, fn pk, acc ->
        acc <> <<33::8, pk::binary>>
      end)

    <<op_m::8, key_pushes::binary, op_n::8, Opcodes.op_checkmultisig()::8>>
  end

  @doc """
  Compute the MPKH — 20-byte HASH160 of the serialized multisig script.
  """
  @spec mpkh(multisig_script()) :: <<_::160>>
  def mpkh(ms), do: Crypto.hash160(to_script_bytes(ms))

  @doc """
  Parse a multisig script from raw bytes.

  Expects: `OP_m <pk1_33bytes> … <pkN_33bytes> OP_n OP_CHECKMULTISIG`
  """
  @spec from_script_bytes(binary()) :: {:ok, multisig_script()} | {:error, term()}
  def from_script_bytes(<<op_m::8, rest::binary>>) do
    if op_m < @op_base + 1 or op_m > @op_base + 16 do
      {:error, :invalid_threshold_opcode}
    else
      m = op_m - @op_base
      parse_keys(rest, m, [])
    end
  end

  def from_script_bytes(_), do: {:error, :script_too_short}

  defp parse_keys(<<33::8, pk::binary-size(33), rest::binary>>, m, acc) do
    parse_keys(rest, m, [pk | acc])
  end

  defp parse_keys(<<op_n::8, op_cms::8>>, m, acc) do
    n = length(acc)

    cond do
      op_n != @op_base + n -> {:error, {:key_count_mismatch, op_n - @op_base, n}}
      op_cms != Opcodes.op_checkmultisig() -> {:error, :missing_checkmultisig}
      m > n -> {:error, {:threshold_exceeds_keys, m, n}}
      true -> {:ok, %{threshold: m, public_keys: Enum.reverse(acc)}}
    end
  end

  defp parse_keys(_, _, _), do: {:error, :malformed_multisig_script}

  # -- Locking --

  @doc """
  Create a bare multisig locking script.

  Produces: `OP_m <pk1> … <pkN> OP_n OP_CHECKMULTISIG`
  """
  @spec lock(multisig_script()) :: {:ok, Script.t()} | {:error, term()}
  def lock(ms) do
    Script.from_binary(to_script_bytes(ms))
  end

  # -- Unlocking (standalone bare multisig) --

  defstruct [:private_keys, :multisig, sighash_flag: 0x41]

  @type t :: %__MODULE__{
          private_keys: [PrivateKey.t()],
          multisig: multisig_script(),
          sighash_flag: non_neg_integer()
        }

  @doc """
  Create a P2MPKH unlocker for bare multisig.

  ## Arguments
  - `private_keys` — the m private keys satisfying the threshold
  - `multisig` — the full multisig script
  - `opts` — `:sighash_flag` (default `0x41`)
  """
  @spec unlock([PrivateKey.t()], multisig_script(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def unlock(private_keys, multisig, opts \\ []) do
    if length(private_keys) != multisig.threshold do
      {:error, {:wrong_key_count, multisig.threshold, length(private_keys)}}
    else
      flag = Keyword.get(opts, :sighash_flag, 0x41)

      {:ok,
       %__MODULE__{
         private_keys: private_keys,
         multisig: multisig,
         sighash_flag: flag
       }}
    end
  end

  @doc """
  Sign a transaction input producing a bare multisig unlocking script.

  Produces: `OP_0 <sig1> <sig2> … <sigM>`
  """
  @impl BSV.Transaction.Template
  def sign(%__MODULE__{private_keys: keys, multisig: _ms, sighash_flag: flag}, tx, input_index) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        locking_script_bin = Script.to_binary(source_output.locking_script)
        satoshis = source_output.satoshis

        with {:ok, hash} <-
               Sighash.signature_hash(tx, input_index, locking_script_bin, flag, satoshis) do
          sign_all_keys(keys, hash, flag, [])
        end
    end
  end

  defp sign_all_keys([], _hash, _flag, sigs) do
    sig_chunks = Enum.map(Enum.reverse(sigs), &{:data, &1})
    {:ok, %Script{chunks: [{:data, <<>>} | sig_chunks]}}
  end

  defp sign_all_keys([key | rest], hash, flag, sigs) do
    case PrivateKey.sign(key, hash) do
      {:ok, der_sig} ->
        sig_with_flag = der_sig <> <<flag::8>>
        sign_all_keys(rest, hash, flag, [sig_with_flag | sigs])

      {:error, _} = err ->
        err
    end
  end

  @doc "Estimated unlocking script length: 1 (OP_0) + m * 73."
  @impl BSV.Transaction.Template
  def estimate_length(%__MODULE__{multisig: ms}, _, _) do
    1 + ms.threshold * 73
  end
end
