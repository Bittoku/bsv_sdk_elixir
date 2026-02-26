defmodule BSV.Crypto.RFC6979 do
  @moduledoc """
  RFC 6979 deterministic k generation using HMAC-DRBG (Section 3.2).
  Specialized for secp256k1 with SHA-256 (qlen = hlen = 256).
  """

  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  @doc """
  Generate deterministic k value per RFC 6979 Section 3.2.
  Takes 32-byte private key and 32-byte message hash.
  Returns 32-byte k as binary.
  """
  @spec generate_k(binary(), binary()) :: binary()
  def generate_k(<<privkey::binary-size(32)>>, <<hash::binary-size(32)>>) do
    # bits2octets(h1): reduce mod q if >= q
    h1_int = :binary.decode_unsigned(hash, :big)
    h1_reduced = if h1_int >= @n, do: h1_int - @n, else: h1_int
    bits2octets = <<h1_reduced::unsigned-big-256>>

    # int2octets(x) = privkey (already 32 bytes big-endian)
    x = privkey

    v = :binary.copy(<<0x01>>, 32)
    k = :binary.copy(<<0x00>>, 32)

    # Step d
    k = hmac(k, <<v::binary, 0x00, x::binary, bits2octets::binary>>)
    # Step e
    v = hmac(k, v)
    # Step f
    k = hmac(k, <<v::binary, 0x01, x::binary, bits2octets::binary>>)
    # Step g
    v = hmac(k, v)

    # Step h
    generate_loop(k, v)
  end

  defp generate_loop(k, v) do
    v = hmac(k, v)
    t = :binary.decode_unsigned(v, :big)

    if t >= 1 and t <= @n - 1 do
      v
    else
      k = hmac(k, <<v::binary, 0x00>>)
      v = hmac(k, v)
      generate_loop(k, v)
    end
  end

  defp hmac(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end
end
