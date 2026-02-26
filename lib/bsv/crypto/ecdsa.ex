defmodule BSV.Crypto.ECDSA do
  @moduledoc """
  Pure-Elixir ECDSA signing on secp256k1 with RFC 6979 deterministic nonces.
  """

  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  @n_half div(@n, 2)
  @gx 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  @gy 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  @p 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  @g {@gx, @gy}

  @doc "Sign a 32-byte hash with a 32-byte private key. Returns {:ok, der_binary}."
  @spec sign(binary(), binary()) :: {:ok, binary()}
  def sign(<<privkey::binary-size(32)>>, <<hash::binary-size(32)>>) do
    k_bin = BSV.Crypto.RFC6979.generate_k(privkey, hash)
    <<k::unsigned-big-256>> = k_bin
    <<d::unsigned-big-256>> = privkey
    <<z::unsigned-big-256>> = hash

    {r, s} = sign_with_k(k, d, z)
    {:ok, encode_der(r, s)}
  end

  @doc "ECDSA sign with given k, private key integer, hash integer. Returns {r, s} with low-S."
  @spec sign_with_k(integer(), integer(), integer()) :: {integer(), integer()}
  def sign_with_k(k, d, z) do
    {rx, _ry} = ec_point_mul(k, @g)
    r = rem(rx, @n)
    k_inv = mod_inverse(k, @n)
    s = rem(k_inv * rem(z + r * d, @n), @n)
    s = if s > @n_half, do: @n - s, else: s
    {r, s}
  end

  @doc "EC point multiplication (double-and-add) on secp256k1."
  def ec_point_mul(0, _point), do: :infinity
  def ec_point_mul(_k, :infinity), do: :infinity

  def ec_point_mul(k, point) when k < 0 do
    {x, y} = ec_point_mul(-k, point)
    {x, @p - y}
  end

  def ec_point_mul(1, point), do: point

  def ec_point_mul(k, point) do
    half = ec_point_mul(div(k, 2), point)
    doubled = ec_point_double(half)
    if rem(k, 2) == 0, do: doubled, else: ec_point_add(doubled, point)
  end

  @doc "EC point addition on secp256k1."
  def ec_point_add(:infinity, p), do: p
  def ec_point_add(p, :infinity), do: p

  def ec_point_add({x1, y1}, {x2, y2}) when x1 == x2 and y1 == y2 do
    ec_point_double({x1, y1})
  end

  def ec_point_add({x1, y1}, {x2, y2}) do
    lam = rem(rem(y2 - y1 + @p * 2, @p) * mod_inverse(rem(x2 - x1 + @p * 2, @p), @p), @p)
    x3 = rem(lam * lam - x1 - x2 + @p * 3, @p)
    y3 = rem(lam * (x1 - x3 + @p) - y1 + @p, @p)
    {x3, y3}
  end

  @doc "EC point doubling on secp256k1."
  def ec_point_double(:infinity), do: :infinity

  def ec_point_double({x, y}) do
    lam = rem(rem(3 * x * x, @p) * mod_inverse(2 * y, @p), @p)
    x3 = rem(lam * lam - 2 * x + @p * 2, @p)
    y3 = rem(lam * (x - x3 + @p) - y + @p, @p)
    {x3, y3}
  end

  @doc "Modular inverse using extended Euclidean algorithm."
  def mod_inverse(a, m) do
    {g, x, _} = extended_gcd(rem(a, m) + m, m)
    if g != 1, do: raise("no inverse"), else: rem(rem(x, m) + m, m)
  end

  defp extended_gcd(0, b), do: {b, 0, 1}

  defp extended_gcd(a, b) do
    {g, x, y} = extended_gcd(rem(b, a), a)
    {g, y - div(b, a) * x, x}
  end

  @doc "DER-encode an ECDSA signature from r, s integers."
  @spec encode_der(integer(), integer()) :: binary()
  def encode_der(r, s) do
    r_bin = encode_der_integer(r)
    s_bin = encode_der_integer(s)
    payload = <<0x02, byte_size(r_bin)>> <> r_bin <> <<0x02, byte_size(s_bin)>> <> s_bin
    <<0x30, byte_size(payload)>> <> payload
  end

  @doc "Encode an integer as a DER integer (with leading 0x00 if high bit set)."
  @spec encode_der_integer(integer()) :: binary()
  def encode_der_integer(n) do
    bin = :binary.encode_unsigned(n)
    case bin do
      <<high::1, _::bitstring>> when high == 1 -> <<0>> <> bin
      _ -> bin
    end
  end
end
