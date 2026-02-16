defmodule BSV.PublicKey do
  @moduledoc """
  Bitcoin public key operations: derivation, compression, address generation, verification.
  """

  @enforce_keys [:point]
  defstruct [:point]

  @type t :: %__MODULE__{point: binary()}

  @secp256k1_p 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

  @doc "Derive a compressed public key from a private key."
  @spec from_private_key(BSV.PrivateKey.t()) :: t()
  def from_private_key(%BSV.PrivateKey{raw: raw}) do
    {pub, _priv} = :crypto.generate_key(:ecdh, :secp256k1, raw)
    %__MODULE__{point: do_compress(pub)}
  end

  @doc "Create a public key from raw bytes (33 compressed or 65 uncompressed)."
  @spec from_bytes(binary()) :: {:ok, t()} | {:error, String.t()}
  def from_bytes(<<prefix, _::binary-size(32)>> = bin)
      when prefix in [0x02, 0x03] and byte_size(bin) == 33 do
    {:ok, %__MODULE__{point: bin}}
  end

  def from_bytes(<<0x04, _::binary-size(64)>> = bin) when byte_size(bin) == 65 do
    {:ok, %__MODULE__{point: bin}}
  end

  def from_bytes(_), do: {:error, "invalid public key bytes"}

  @doc "Compress a public key to 33 bytes."
  @spec compress(t()) :: t()
  def compress(%__MODULE__{point: <<prefix, _::binary-size(32)>>} = key)
      when prefix in [0x02, 0x03],
      do: key

  def compress(%__MODULE__{point: point}), do: %__MODULE__{point: do_compress(point)}

  @doc "Decompress a public key to 65 bytes."
  @spec decompress(t()) :: {:ok, t()}
  def decompress(%__MODULE__{point: <<0x04, _::binary-size(64)>>} = key), do: {:ok, key}

  def decompress(%__MODULE__{point: <<prefix_byte, x::binary-size(32)>>}) do
    p = @secp256k1_p
    x_int = :binary.decode_unsigned(x, :big)
    y_sq = rem(rem(x_int * x_int * x_int + 7, p) + p, p)
    y = mod_pow(y_sq, div(p + 1, 4), p)
    expected_parity = prefix_byte - 0x02
    y_final = if rem(y, 2) == expected_parity, do: y, else: p - y
    y_bin = :binary.encode_unsigned(y_final, :big) |> pad_to(32)
    {:ok, %__MODULE__{point: <<0x04, x::binary, y_bin::binary>>}}
  end

  @doc "Generate a Bitcoin address from this public key."
  @spec to_address(t(), keyword()) :: String.t()
  def to_address(%__MODULE__{} = key, opts \\ []) do
    network = Keyword.get(opts, :network, :mainnet)
    version = if network == :mainnet, do: 0x00, else: 0x6F
    compressed_point = compress(key).point
    hash = BSV.Crypto.hash160(compressed_point)
    BSV.Base58.check_encode(hash, version)
  end

  @doc """
  Compute ECDH shared secret (delegates to private key).
  """
  @spec derive_shared_secret(t(), BSV.PrivateKey.t()) :: {:ok, t()} | {:error, String.t()}
  def derive_shared_secret(%__MODULE__{} = pub_key, %BSV.PrivateKey{} = priv_key) do
    BSV.PrivateKey.derive_shared_secret(priv_key, pub_key)
  end

  @doc """
  Derive a child public key using BRC-42 key derivation.

  Computes ECDH shared secret with the private key, then
  HMAC-SHA256(shared_secret_compressed, invoice_number) to derive a scalar,
  multiplies G by that scalar, and adds the result to this public key point.
  """
  @spec derive_child(t(), BSV.PrivateKey.t(), String.t()) :: {:ok, t()} | {:error, String.t()}
  def derive_child(%__MODULE__{} = pub_key, %BSV.PrivateKey{} = priv_key, invoice_number) do
    with {:ok, shared_secret} <- BSV.PrivateKey.derive_shared_secret(priv_key, pub_key) do
      shared_compressed = shared_secret.point
      hmac = BSV.Crypto.sha256_hmac(invoice_number, shared_compressed)
      # G * hmac_scalar => a new public key point
      # We create a temporary private key from the hmac scalar, get its public key, then add
      case BSV.PrivateKey.from_bytes(hmac) do
        {:ok, offset_key} ->
          offset_pub = from_private_key(offset_key)
          # Point addition: decompress both, add on curve
          point_add(pub_key, offset_pub)

        {:error, _} ->
          {:error, "derived hmac scalar out of range"}
      end
    end
  end

  @doc false
  @spec point_add(t(), t()) :: {:ok, t()} | {:error, String.t()}
  def point_add(%__MODULE__{} = a, %__MODULE__{} = b) do
    # Use the erlang crypto to do EC point addition via a trick:
    # We decompress both points, extract coordinates, and do modular arithmetic
    {:ok, %{point: <<0x04, ax::binary-size(32), ay::binary-size(32)>>}} = decompress(a)
    {:ok, %{point: <<0x04, bx::binary-size(32), by::binary-size(32)>>}} = decompress(b)

    p = @secp256k1_p
    ax_int = :binary.decode_unsigned(ax, :big)
    ay_int = :binary.decode_unsigned(ay, :big)
    bx_int = :binary.decode_unsigned(bx, :big)
    by_int = :binary.decode_unsigned(by, :big)

    if ax_int == bx_int and ay_int == by_int do
      # Point doubling
      lambda = mod_mul(mod_mul(3, mod_mul(ax_int, ax_int, p), p), mod_inv(mod_mul(2, ay_int, p), p), p)
      rx = mod_sub(mod_mul(lambda, lambda, p), mod_mul(2, ax_int, p), p)
      ry = mod_sub(mod_mul(lambda, mod_sub(ax_int, rx, p), p), ay_int, p)
      encode_point(rx, ry)
    else
      # Point addition
      lambda = mod_mul(mod_sub(by_int, ay_int, p), mod_inv(mod_sub(bx_int, ax_int, p), p), p)
      rx = mod_sub(mod_sub(mod_mul(lambda, lambda, p), ax_int, p), bx_int, p)
      ry = mod_sub(mod_mul(lambda, mod_sub(ax_int, rx, p), p), ay_int, p)
      encode_point(rx, ry)
    end
  end

  defp encode_point(x, y) do
    x_bin = :binary.encode_unsigned(x, :big) |> pad_to(32)
    y_bin = :binary.encode_unsigned(y, :big) |> pad_to(32)
    from_bytes(<<0x04, x_bin::binary, y_bin::binary>>)
    |> then(fn {:ok, pk} -> {:ok, compress(pk)} end)
  end

  defp mod_mul(a, b, m), do: rem(a * b, m)
  defp mod_sub(a, b, m), do: rem(a - b + m, m)
  defp mod_inv(a, m), do: mod_pow(a, m - 2, m)

  @doc "Verify a signature against a message hash."
  @spec verify(t(), binary(), binary()) :: boolean()
  def verify(%__MODULE__{point: point}, <<message_hash::binary-size(32)>>, signature_der) do
    :crypto.verify(:ecdsa, :sha256, {:digest, message_hash}, signature_der, [point, :secp256k1])
  end

  defp do_compress(<<0x04, x::binary-size(32), y::binary-size(32)>>) do
    last_byte = :binary.at(y, 31)
    prefix = if rem(last_byte, 2) == 0, do: 0x02, else: 0x03
    <<prefix, x::binary>>
  end

  defp do_compress(<<prefix, _::binary-size(32)>> = compressed)
       when prefix in [0x02, 0x03] do
    compressed
  end

  defp mod_pow(base, exp, mod) do
    :crypto.mod_pow(base, exp, mod) |> :binary.decode_unsigned(:big)
  end

  defp pad_to(bin, len) when byte_size(bin) >= len, do: bin
  defp pad_to(bin, len), do: :binary.copy(<<0>>, len - byte_size(bin)) <> bin
end
