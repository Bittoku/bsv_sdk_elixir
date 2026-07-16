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
  Returns `true` if and only if both binaries are byte-for-byte equal, `false`
  otherwise (including any length difference). Runtime is independent of both
  content AND length differences.

  Each input is first reduced to its 32-byte SHA-256 digest, then the two
  digests are compared in constant time. Because the digests are always the same
  length, the comparison leaks nothing about the inputs' lengths; and because
  SHA-256 is collision-resistant, `SHA256(a) == SHA256(b)` iff `a == b` — so
  inputs of different length or content produce different digests and compare
  unequal.
  """
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(a, b) when is_binary(a) and is_binary(b) do
    # Hash EACH input separately (NOT the concatenations `a <> b` / `b <> a`,
    # which are equal whenever the pieces commute — e.g. "" <> "x" == "x" <> "",
    # so unequal inputs would compare equal). Two equal-length digests can then
    # be compared in constant time.
    ha = :crypto.hash(:sha256, a)
    hb = :crypto.hash(:sha256, b)

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
