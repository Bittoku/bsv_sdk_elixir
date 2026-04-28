defmodule BSV.Tokens.Stas3.EngineVerify do
  @moduledoc """
  End-to-end script-engine verification helper for STAS 3.0 transactions.

  Given a fully-signed transaction produced by `BSV.Tokens.Factory.Stas3`,
  this module pulls out the unlocking script for a single input, builds a
  BIP-143 + ECDSA `sighash_fn`, and runs `BSV.Script.Interpreter.verify/3`
  against that input's previous locking script.

  This is the canonical end-to-end smoke check for STAS 3.0 in this SDK:
  if `verify/4` returns `:ok`, the engine has accepted the transaction's
  unlock-vs-lock pair.

  Output:

    * `:ok` — interpreter accepted the script pair.
    * `{:error, reason}` — interpreter rejected, with `reason` propagated
      from the interpreter (e.g. `:invalid_split_range`,
      `:checksigverify_failed`, `:eval_false`).
  """

  alias BSV.Script
  alias BSV.Transaction
  alias BSV.Transaction.Sighash

  @default_flags [:utxo_after_genesis, :enable_sighash_forkid]

  @doc """
  Verify a single input of `tx` against `prev_locking_script` (the
  locking script of the UTXO that input is spending) using the SDK's
  full script interpreter and a real BIP-143 sighash function.

  ## Options

    * `:flags` — interpreter flags. Defaults to
      `[:utxo_after_genesis, :enable_sighash_forkid]`.
    * `:trace` — when `true`, asks the interpreter for an opcode-level
      trace and writes it to `:trace_path` (default `/tmp/stas3_engine_trace.log`).
  """
  @spec verify(
          Transaction.t(),
          non_neg_integer(),
          Script.t(),
          non_neg_integer(),
          keyword()
        ) :: :ok | {:error, term()}
  def verify(%Transaction{} = tx, input_index, %Script{} = prev_lock, prev_amount, opts \\ [])
      when is_integer(input_index) and is_integer(prev_amount) do
    input = Enum.at(tx.inputs, input_index)
    unlock = input.unlocking_script

    sighash_fn = fn sig_der, pubkey_bin, sighash_type ->
      case Sighash.signature_hash(
             tx,
             input_index,
             Script.to_binary(prev_lock),
             sighash_type,
             prev_amount
           ) do
        {:ok, hash} ->
          ok =
            :crypto.verify(:ecdsa, :sha256, {:digest, hash}, sig_der, [pubkey_bin, :secp256k1])

          {:ok, ok}

        {:error, _} = err ->
          err
      end
    end

    flags = Keyword.get(opts, :flags, @default_flags)

    interp_opts =
      [flags: flags, sighash_fn: sighash_fn]
      |> maybe_put_trace(opts)

    BSV.Script.Interpreter.verify(unlock, prev_lock, interp_opts)
  end

  defp maybe_put_trace(interp_opts, opts) do
    case Keyword.get(opts, :trace, false) do
      false ->
        interp_opts

      true ->
        path = Keyword.get(opts, :trace_path, "/tmp/stas3_engine_trace.log")
        Keyword.merge(interp_opts, trace: true, trace_path: path)
    end
  end
end
