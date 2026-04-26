defmodule BSV.Transaction.P2MPKH do
  @moduledoc """
  Pay-to-Multiple-Public-Key-Hash (P2MPKH) signing template — STAS 3.0 v0.1 §10.2.

  ## Module purpose

  This module implements the wire-format helpers needed to construct, parse,
  hash, lock, and spend P2MPKH redeem-buffers as specified in the STAS 3.0
  protocol specification v0.1 (section 10.2). It is used at issuance and
  redemption boundaries of a STAS token's lifecycle, and to derive the MPKH
  (HASH160 of the redeem buffer) used as the owner / arbitrator anchor inside
  STAS 3 in-life UTXOs.

  ## Wire format (per STAS 3.0 v0.1 §10.2)

  The "redeem script" (a.k.a. redeem buffer / multisig script) is exactly:

      [m: 1B raw 0x01..0x05]
        [0x21][pk1: 33B compressed SEC1]
        [0x21][pk2: 33B compressed SEC1]
        ...
        [0x21][pkN: 33B compressed SEC1]
      [n: 1B raw 0x01..0x05]

  Total length = `2 + 34*N` bytes. Constraints: `1 <= m <= n <= 5`.

  Note: `m` and `n` are **raw threshold bytes** (not OP_m / OP_n opcodes),
  and there is **no trailing OP_CHECKMULTISIG**. The template / engine
  re-builds the multisig script when verifying signatures.

  ## MPKH

  `MPKH = HASH160(redeem_buffer)`. The 20-byte MPKH is what appears in the
  fixed 70-byte P2MPKH locking script and inside STAS 3 token UTXOs.

  ## Unlocking stack (P2MPKH spend)

  Per spec §10.2 line 414/434:

      OP_0 <sig_1> <sig_2> ... <sig_m> <redeem_buffer>

  The leading `OP_0` is the OP_CHECKMULTISIG dummy.

  ## Functions

  - `new_multisig/2` — validate and wrap a (threshold, public keys) tuple.
  - `to_script_bytes/1` — emit the spec wire format described above.
  - `from_script_bytes/1` — parse the spec wire format. Rejects any other form.
  - `mpkh/1` — HASH160 of the redeem buffer.
  - `lock/1` — wrap the redeem buffer as a `BSV.Script.t()` (used as the
    "redemption script" data push, NOT a P2MPKH locking script — for the
    70-byte fixed locking script see `BSV.Tokens.Script.Templates`).
  - `unlock/3` + `sign/3` — produce the P2MPKH unlocking script
    `OP_0 <sigs...> <redeem_buffer>`.
  - `estimate_length/3` — size estimate of the unlocking script bytes.
  """

  @behaviour BSV.Transaction.Template

  alias BSV.{Crypto, Script, PrivateKey}
  alias BSV.Transaction.Sighash

  # Per spec v0.1 §10.2: 1 <= m <= n <= 5
  @max_keys 5

  # -- MultisigScript helpers --

  @type multisig_script :: %{
          threshold: pos_integer(),
          public_keys: [binary()]
        }

  @doc """
  Create a new multisig script map.

  ## Arguments
  - `threshold` — minimum signatures required (m), 1..5
  - `public_keys` — list of 33-byte compressed SEC1 public keys, length 1..5

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

  @doc """
  Serialize a multisig script to the STAS 3.0 v0.1 §10.2 redeem-buffer bytes.

  ## Input
  - `multisig_script()` map with `:threshold` (1..5) and `:public_keys` (1..5
    compressed 33-byte keys).

  ## Output
  Binary of length `2 + 34*N` shaped as:

      <m::8> (<<0x21, pk_i::binary-size(33)>> for each pk_i) <n::8>

  where both `m` and `n` are raw bytes (NOT OP_m / OP_n).
  """
  @spec to_script_bytes(multisig_script()) :: binary()
  def to_script_bytes(%{threshold: m, public_keys: pks})
      when is_integer(m) and m >= 1 and m <= @max_keys do
    n = length(pks)

    if n < 1 or n > @max_keys do
      raise ArgumentError, "P2MPKH n must be in 1..#{@max_keys}, got #{n}"
    end

    if m > n do
      raise ArgumentError, "P2MPKH threshold m=#{m} exceeds key count n=#{n}"
    end

    key_pushes =
      Enum.reduce(pks, <<>>, fn pk, acc ->
        acc <> <<0x21, pk::binary>>
      end)

    <<m::8, key_pushes::binary, n::8>>
  end

  @doc """
  Compute the MPKH — 20-byte HASH160 of the serialized redeem buffer.

  ## Input
  - `multisig_script()` map.

  ## Output
  20-byte binary (`<<_::160>>`).
  """
  @spec mpkh(multisig_script()) :: <<_::160>>
  def mpkh(ms), do: Crypto.hash160(to_script_bytes(ms))

  @doc """
  Parse a STAS 3.0 v0.1 §10.2 redeem-buffer back into a multisig script map.

  ## Input
  - Binary produced by `to_script_bytes/1`. Length must equal `2 + 34*N` for
    some `N` in 1..5, and the leading byte `m` and trailing byte `n` must
    satisfy `1 <= m <= n <= 5`.

  ## Output
  `{:ok, multisig_script()}` on success, `{:error, reason}` on any deviation
  from the wire format. The function deliberately rejects any other shape
  (no support for the legacy OP_m / OP_CHECKMULTISIG form).
  """
  @spec from_script_bytes(binary()) :: {:ok, multisig_script()} | {:error, term()}
  def from_script_bytes(<<m::8, rest::binary>>) when m >= 1 and m <= @max_keys do
    parse_keys(rest, m, [])
  end

  def from_script_bytes(<<m::8, _::binary>>) when m >= 0 and m <= 255 do
    {:error, {:invalid_threshold, m}}
  end

  def from_script_bytes(_), do: {:error, :script_too_short}

  defp parse_keys(<<0x21, pk::binary-size(33), rest::binary>>, m, acc) do
    parse_keys(rest, m, [pk | acc])
  end

  defp parse_keys(<<n::8>>, m, acc) when n >= 1 and n <= @max_keys do
    count = length(acc)

    cond do
      n != count -> {:error, {:key_count_mismatch, n, count}}
      m > n -> {:error, {:threshold_exceeds_keys, m, n}}
      true -> {:ok, %{threshold: m, public_keys: Enum.reverse(acc)}}
    end
  end

  defp parse_keys(_, _, _), do: {:error, :malformed_multisig_script}

  # -- Locking --

  @doc """
  Build a `BSV.Script.t()` whose only chunk is the redeem-buffer push.

  This is convenient when the SDK needs to embed the redeem buffer as a
  data push (e.g. as the last item on the unlocking stack). It is **not**
  the fixed 70-byte P2MPKH locking script — for that, see
  `BSV.Tokens.Script.Templates.p2mpkh_locking_script/1`.

  ## Input
  - `multisig_script()` map.

  ## Output
  `{:ok, %BSV.Script{chunks: [{:data, redeem_buffer}]}}`.
  """
  @spec lock(multisig_script()) :: {:ok, Script.t()}
  def lock(ms) do
    {:ok, %Script{chunks: [{:data, to_script_bytes(ms)}]}}
  end

  # -- Unlocking (P2MPKH spend) --

  defstruct [:private_keys, :multisig, sighash_flag: 0x41]

  @type t :: %__MODULE__{
          private_keys: [PrivateKey.t()],
          multisig: multisig_script(),
          sighash_flag: non_neg_integer()
        }

  @doc """
  Create a P2MPKH unlocker.

  ## Arguments
  - `private_keys` — exactly `m` private keys satisfying the threshold
  - `multisig` — the multisig script the UTXO commits to
  - `opts` — `:sighash_flag` (default `0x41` = SIGHASH_ALL | SIGHASH_FORKID)

  ## Returns
  `{:ok, t()}` on success, `{:error, term()}` if the key count does not
  match the threshold.
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
  Sign a transaction input producing a P2MPKH unlocking script.

  ## Output
  `{:ok, %BSV.Script{}}` whose chunks (in order) are:

      OP_0 (as {:data, <<>>}),
      <sig_1>, <sig_2>, ..., <sig_m>,
      <redeem_buffer>

  per STAS 3.0 v0.1 §10.2 line 414/434.
  """
  @impl BSV.Transaction.Template
  def sign(%__MODULE__{private_keys: keys, multisig: ms, sighash_flag: flag}, tx, input_index) do
    input = Enum.at(tx.inputs, input_index)

    case input.source_output do
      nil ->
        {:error, :missing_source_output}

      source_output ->
        locking_script_bin = Script.to_binary(source_output.locking_script)
        satoshis = source_output.satoshis

        with {:ok, hash} <-
               Sighash.signature_hash(tx, input_index, locking_script_bin, flag, satoshis) do
          sign_all_keys(keys, hash, flag, [], ms)
        end
    end
  end

  defp sign_all_keys([], _hash, _flag, sigs, ms) do
    sig_chunks = Enum.map(Enum.reverse(sigs), &{:data, &1})
    redeem = to_script_bytes(ms)
    {:ok, %Script{chunks: [{:data, <<>>} | sig_chunks] ++ [{:data, redeem}]}}
  end

  defp sign_all_keys([key | rest], hash, flag, sigs, ms) do
    case PrivateKey.sign(key, hash) do
      {:ok, der_sig} ->
        sig_with_flag = der_sig <> <<flag::8>>
        sign_all_keys(rest, hash, flag, [sig_with_flag | sigs], ms)

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Estimate the unlocking script length in bytes.

  Layout: `OP_0 (1B) + m * 73B (sig pushes) + push prefix for redeem
  (2B PUSHDATA1) + redeem buffer (2 + 34*n)` = `m*73 + 34*n + 5`.
  """
  @impl BSV.Transaction.Template
  def estimate_length(%__MODULE__{multisig: ms}, _, _) do
    m = ms.threshold
    n = length(ms.public_keys)
    m * 73 + 34 * n + 5
  end
end
