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
end
