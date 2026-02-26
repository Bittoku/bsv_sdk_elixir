defmodule BSV.Contract.P2RPH do
  @moduledoc """
  Pay to R-Puzzle Hash contract.

  P2RPH scripts lock Bitcoin to a hash puzzle based on the R value of an ECDSA
  signature. The funds can be unlocked with knowledge of the corresponding K
  value (the ECDSA nonce), allowing the spending party to sign with **any** key pair.

  ## Lock parameters
  - `:r_hash` — 20-byte HASH160 of the R value (preferred)
  - `:r` — raw R value binary (will be HASH160'd automatically)

  ## Unlock parameters
  - `:privkey` — a `BSV.PrivateKey.t()` (any key pair works)
  - `:k` — the K value (ECDSA nonce) as a 32-byte binary
  - `:pubkey` — the corresponding compressed public key binary

  ## How it works

  The locking script extracts the R value from a signature on the stack,
  hashes it, and compares against the committed hash. Two signatures are required:
  one with the known K value (proving knowledge of K), and a standard signature
  from any key pair.

  ## Example

      k = BSV.Contract.P2RPH.generate_k()
      r = BSV.Contract.P2RPH.get_r(k)

      # Lock
      contract = P2RPH.lock(1000, %{r: r})

      # Unlock (with any keypair)
      contract = P2RPH.unlock(utxo, %{
        privkey: my_privkey,
        k: k,
        pubkey: my_pubkey_bin
      })
  """
  use BSV.Contract

  alias BSV.{Crypto, PrivateKey}

  # secp256k1 curve parameters
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  @gx 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  @gy 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  @p 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

  @impl true
  def locking_script(ctx, %{r_hash: r_hash}) when byte_size(r_hash) == 20 do
    do_locking_script(ctx, r_hash)
  end

  def locking_script(ctx, %{r: r}) when is_binary(r) do
    r_hash = Crypto.hash160(r)
    do_locking_script(ctx, r_hash)
  end

  defp do_locking_script(ctx, r_hash) do
    ctx
    |> op_over()
    |> op_3()
    |> op_split()
    |> op_nip()
    |> op_1()
    |> op_split()
    |> op_swap()
    |> op_split()
    |> op_drop()
    |> op_hash160()
    |> push(r_hash)
    |> op_equalverify()
    |> op_tuck()
    |> op_checksigverify()
    |> op_checksig()
  end

  @impl true
  def unlocking_script(ctx, %{privkey: %PrivateKey{} = privkey, k: k, pubkey: pubkey})
      when is_binary(k) and is_binary(pubkey) do
    ctx
    |> sig(privkey)
    |> sig_with_k(privkey, k)
    |> push(pubkey)
  end

  @doc """
  Generate a random K value (32-byte binary).
  """
  @spec generate_k() :: binary()
  def generate_k do
    <<k::unsigned-big-256>> = :crypto.strong_rand_bytes(32)
    k = rem(k, @n)
    if k == 0, do: generate_k(), else: <<k::unsigned-big-256>>
  end

  @doc """
  Compute the R value (compressed point x-coordinate) from a K value.
  Returns the R value as a binary, with a leading 0x00 byte if the high bit is set.
  """
  @spec get_r(binary()) :: binary()
  def get_r(<<k::unsigned-big-256>>) do
    {rx, _ry} = ec_point_mul(k, {@gx, @gy})
    r = rem(rx, @n)

    r_bin = <<r::unsigned-big-256>>

    case r_bin do
      <<high::1, _::bitstring>> when high == 1 -> <<0>> <> r_bin
      _ -> r_bin
    end
  end

  # Sign a message hash with a specific k value (for R-puzzle proofs)
  defp sig_with_k(
         %BSV.Contract{
           ctx: {tx, vin},
           opts: opts,
           subject: %{source_output: source_output}
         } = ctx,
         %PrivateKey{raw: privkey_raw},
         <<k::unsigned-big-256>>
       )
       when not is_nil(source_output) do
    sighash_flag = Keyword.get(opts, :sighash_flag, 0x41)
    locking_script_bin = BSV.Script.to_binary(source_output.locking_script)
    satoshis = source_output.satoshis

    {:ok, hash} =
      BSV.Transaction.Sighash.signature_hash(tx, vin, locking_script_bin, sighash_flag, satoshis)

    <<z::unsigned-big-256>> = hash
    <<d::unsigned-big-256>> = privkey_raw

    # ECDSA sign with custom k
    {rx, _ry} = ec_point_mul(k, {@gx, @gy})
    r = rem(rx, @n)
    k_inv = mod_inverse(k, @n)
    s = rem(k_inv * rem(z + r * d, @n), @n)

    # Low-S normalization
    s = if s > div(@n, 2), do: @n - s, else: s

    der = encode_der_signature(r, s)
    signature = der <> <<sighash_flag::8>>
    BSV.Contract.script_push(ctx, {:data, signature})
  end

  defp sig_with_k(%BSV.Contract{} = ctx, _privkey, _k) do
    BSV.Contract.script_push(ctx, {:data, <<0::568>>})
  end

  # Modular inverse using extended Euclidean algorithm
  defp mod_inverse(a, m) do
    {g, x, _} = extended_gcd(rem(a, m) + m, m)
    if g != 1, do: raise("no inverse"), else: rem(rem(x, m) + m, m)
  end

  defp extended_gcd(0, b), do: {b, 0, 1}

  defp extended_gcd(a, b) do
    {g, x, y} = extended_gcd(rem(b, a), a)
    {g, y - div(b, a) * x, x}
  end

  # EC point multiplication on secp256k1 (double-and-add)
  defp ec_point_mul(0, _point), do: :infinity
  defp ec_point_mul(_k, :infinity), do: :infinity

  defp ec_point_mul(k, point) when k < 0 do
    {x, y} = ec_point_mul(-k, point)
    {x, @p - y}
  end

  defp ec_point_mul(1, point), do: point

  defp ec_point_mul(k, point) do
    half = ec_point_mul(div(k, 2), point)
    doubled = ec_point_double(half)

    if rem(k, 2) == 0 do
      doubled
    else
      ec_point_add(doubled, point)
    end
  end

  defp ec_point_add(:infinity, p), do: p
  defp ec_point_add(p, :infinity), do: p

  defp ec_point_add({x1, y1}, {x2, y2}) when x1 == x2 and y1 == y2 do
    ec_point_double({x1, y1})
  end

  defp ec_point_add({x1, y1}, {x2, y2}) do
    lam = rem(rem(y2 - y1 + @p * 2, @p) * mod_inverse(rem(x2 - x1 + @p * 2, @p), @p), @p)
    x3 = rem(lam * lam - x1 - x2 + @p * 3, @p)
    y3 = rem(lam * (x1 - x3 + @p) - y1 + @p, @p)
    {x3, y3}
  end

  defp ec_point_double(:infinity), do: :infinity

  defp ec_point_double({x, y}) do
    lam = rem(rem(3 * x * x, @p) * mod_inverse(2 * y, @p), @p)
    x3 = rem(lam * lam - 2 * x + @p * 2, @p)
    y3 = rem(lam * (x - x3 + @p) - y + @p, @p)
    {x3, y3}
  end

  # DER encode an ECDSA signature {r, s}
  defp encode_der_signature(r, s) do
    r_bin = encode_der_integer(r)
    s_bin = encode_der_integer(s)
    payload = <<0x02, byte_size(r_bin)>> <> r_bin <> <<0x02, byte_size(s_bin)>> <> s_bin
    <<0x30, byte_size(payload)>> <> payload
  end

  defp encode_der_integer(n) do
    bin = :binary.encode_unsigned(n)

    case bin do
      <<high::1, _::bitstring>> when high == 1 -> <<0>> <> bin
      _ -> bin
    end
  end
end
