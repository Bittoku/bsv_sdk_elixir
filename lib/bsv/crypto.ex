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
  Constant-time binary comparison.

  Prevents timing side-channel attacks when comparing secrets (HMACs, keys, etc.).
  Returns `true` if both binaries are equal, `false` otherwise.
  Always examines every byte regardless of where the first difference occurs.
  """
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(a, b) when is_binary(a) and is_binary(b) do
    # Hash both inputs first to make timing independent of length differences.
    # This prevents leaking length information through early return.
    ha = :crypto.hash(:sha256, a)
    hb = :crypto.hash(:sha256, b)

    equal_hashes =
      if function_exported?(:crypto, :hash_equals, 2) do
        :crypto.hash_equals(ha, hb)
      else
        ha_bytes = :binary.bin_to_list(ha)
        hb_bytes = :binary.bin_to_list(hb)

        Enum.zip(ha_bytes, hb_bytes)
        |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)
        |> Kernel.==(0)
      end

    equal_hashes and byte_size(a) == byte_size(b)
  end
end
