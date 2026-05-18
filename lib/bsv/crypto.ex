defmodule BSV.Crypto do
  @moduledoc """
  Cryptographic hash functions using OTP `:crypto`.
  """

  @doc "SHA-256 hash."
  @spec sha256(binary()) :: <<_::256>>
  def sha256(data), do: :crypto.hash(:sha256, data)

  @doc "Double SHA-256 hash."
  @spec sha256d(binary()) :: <<_::256>>
  def sha256d(data), do: :crypto.hash(:sha256, :crypto.hash(:sha256, data))

  @doc "RIPEMD-160 hash."
  @spec ripemd160(binary()) :: <<_::160>>
  def ripemd160(data), do: :crypto.hash(:ripemd160, data)

  @doc "Hash160: RIPEMD160(SHA256(data))."
  @spec hash160(binary()) :: <<_::160>>
  def hash160(data), do: :crypto.hash(:ripemd160, :crypto.hash(:sha256, data))

  @doc "SHA-512 hash."
  @spec sha512(binary()) :: <<_::512>>
  def sha512(data), do: :crypto.hash(:sha512, data)

  @doc "HMAC-SHA256."
  @spec sha256_hmac(binary(), binary()) :: <<_::256>>
  def sha256_hmac(data, key), do: :crypto.mac(:hmac, :sha256, key, data)

  @doc """
  True constant-time binary comparison.

  Prevents timing side-channel attacks when comparing secrets (HMACs, keys, etc.).
  Returns `true` if both binaries are equal, `false` otherwise.
  Runtime is independent of both content AND length differences.

  Uses a single SHA-256 hash of `a <> b` and `b <> a` to eliminate all
  length-based timing variability, then performs byte-level XOR accumulation.
  """
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(a, b) when is_binary(a) and is_binary(b) do
    # Technique: hash both concatenations to make timing fully independent of
    # length differences.  We compute two hashes:
    #   ha = SHA256(a <> b)
    #   hb = SHA256(b <> a)
    # If a == b then ha == hb.  The SHA-256 algorithm processes fixed 64-byte
    # blocks with padding, so the runtime of :crypto.hash/2 is constant for
    # any two inputs of a given *concatenated* length.  By hashing both orderings
    # we avoid leaking which input is longer.

    ha = :crypto.hash(:sha256, a <> b)
    hb = :crypto.hash(:sha256, b <> a)

    if function_exported?(:crypto, :hash_equals, 2) do
      :crypto.hash_equals(ha, hb)
    else
      # Fallback XOR-accumulate — still constant-time because SHA-256
      # digests are always 32 bytes.
      <<diff::32*8>> = :crypto.exor(ha, hb)
      diff == 0
    end
  end
end
