defmodule BSV.PrivateKey do
  @moduledoc """
  Bitcoin private key operations: generation, WIF encoding, signing.

  ## OpenSSL Requirement

  Signing requires OpenSSL 3.0+ for RFC 6979 deterministic nonce generation.
  Earlier OpenSSL versions may use random k-values, which is unsafe if the same
  message is signed across different OpenSSL configurations.

  ## Security Notice — Key Material Lifetime

  Private key bytes (`raw` field) persist in BEAM process memory until garbage
  collected. Erlang/Elixir binaries are immutable and the GC is non-deterministic,
  so key material **cannot be reliably zeroed** from pure Elixir.

  **Mitigations for production use:**

  - Run signing operations in dedicated short-lived processes (GenServer / Task)
    so that key memory is reclaimed when the process exits.
  - Consider NIF-backed secure memory (e.g. `libsodium` `sodium_mlock`/`sodium_munlock`)
    for long-lived key storage.
  - Avoid logging or inspecting `PrivateKey` structs.
  - Be aware that BEAM crash dumps may contain key material.
  """

  @enforce_keys [:raw]
  defstruct [:raw]

  @type t :: %__MODULE__{raw: <<_::256>>}

  # secp256k1 curve order
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  @n_half div(@n, 2)

  @doc "Generate a random private key."
  @spec generate() :: t()
  def generate do
    raw = :crypto.strong_rand_bytes(32)
    val = :binary.decode_unsigned(raw, :big)

    if val > 0 and val < @n do
      %__MODULE__{raw: raw}
    else
      generate()
    end
  end

  @doc "Create a private key from 32 raw bytes."
  @spec from_bytes(binary()) :: {:ok, t()} | {:error, String.t()}
  def from_bytes(<<raw::binary-size(32)>>) do
    val = :binary.decode_unsigned(raw, :big)

    if val > 0 and val < @n do
      {:ok, %__MODULE__{raw: raw}}
    else
      {:error, "private key out of range"}
    end
  end

  def from_bytes(_), do: {:error, "private key must be 32 bytes"}

  @doc "Encode private key to WIF format."
  @spec to_wif(t(), keyword()) :: String.t()
  def to_wif(%__MODULE__{raw: raw}, opts \\ []) do
    network = Keyword.get(opts, :network, :mainnet)
    compressed = Keyword.get(opts, :compressed, true)
    prefix = if network == :mainnet, do: 0x80, else: 0xEF
    suffix = if compressed, do: <<0x01>>, else: <<>>
    BSV.Base58.check_encode(raw <> suffix, prefix)
  end

  @doc "Decode a WIF string to a private key."
  @spec from_wif(String.t()) :: {:ok, t()} | {:error, String.t()}
  def from_wif(wif) do
    with {:ok, {version, payload}} <- BSV.Base58.check_decode(wif),
         true <- version in [0x80, 0xEF] || {:error, "invalid WIF version"} do
      case payload do
        <<raw::binary-size(32), 0x01>> -> from_bytes(raw)
        <<raw::binary-size(32)>> -> from_bytes(raw)
        _ -> {:error, "invalid WIF payload length"}
      end
    end
  end

  @doc "Decode a WIF string, raising on error."
  @spec from_wif!(String.t()) :: t()
  def from_wif!(wif) do
    case from_wif(wif) do
      {:ok, key} -> key
      {:error, reason} -> raise ArgumentError, reason
    end
  end

  @doc "Sign a 32-byte message hash with this key. Returns DER-encoded signature with low-S."
  @spec sign(t(), binary()) :: {:ok, binary()}
  def sign(%__MODULE__{raw: raw}, <<message_hash::binary-size(32)>>) do
    der = :crypto.sign(:ecdsa, :sha256, {:digest, message_hash}, [raw, :secp256k1])
    {:ok, normalize_low_s(der)}
  end

  @doc "Derive the public key from this private key."
  @spec to_public_key(t()) :: BSV.PublicKey.t()
  def to_public_key(%__MODULE__{} = key) do
    BSV.PublicKey.from_private_key(key)
  end

  @doc """
  Compute ECDH shared secret with a public key.

  Uses OpenSSL-backed `:crypto.compute_key/4` for security (includes curve
  validation) and performance. Returns the shared point as a compressed public key.
  """
  @spec derive_shared_secret(t(), BSV.PublicKey.t()) :: {:ok, BSV.PublicKey.t()} | {:error, String.t()}
  def derive_shared_secret(%__MODULE__{raw: raw}, %BSV.PublicKey{} = pub_key) do
    # Decompress to get the 65-byte uncompressed point for :crypto
    {:ok, decompressed} = BSV.PublicKey.decompress(pub_key)

    try do
      # :crypto.compute_key returns the raw x-coordinate of the shared point
      shared_x = :crypto.compute_key(:ecdh, decompressed.point, raw, :secp256k1)

      # Reconstruct as a compressed public key (we only need x, pick even y)
      x_padded = pad_to(shared_x, 32)

      # Compute the full point to get a valid compressed key
      # Use :crypto.generate_key with the shared_x as a "private key" won't work;
      # instead, treat the x-coord and compute y to form a valid point.
      # The shared secret in BRC-42 is used as a compressed point, so we need
      # to reconstruct it. Since :crypto.compute_key returns just x, we need y.
      p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
      x_int = :binary.decode_unsigned(x_padded, :big)
      y_sq = rem(rem(x_int * x_int * x_int + 7, p) + p, p)
      y = :crypto.mod_pow(y_sq, div(p + 1, 4), p) |> :binary.decode_unsigned(:big)

      # Verify y is valid
      if rem(y * y, p) != y_sq do
        {:error, "ECDH shared secret not on curve"}
      else
        # Use even y (0x02 prefix)
        y_final = if rem(y, 2) == 0, do: y, else: p - y
        _ = y_final
        # Return compressed with 0x02 prefix (even y)
        {:ok, %BSV.PublicKey{point: <<0x02, x_padded::binary>>}}
      end
    rescue
      e in [ErlangError, ArgumentError] -> {:error, "ECDH computation failed: #{inspect(e)}"}
    end
  end

  @doc """
  Derive a child private key using BRC-42 key derivation.

  Computes ECDH shared secret with the counterparty's public key, then
  HMAC-SHA256(shared_secret_compressed, invoice_number) to derive a scalar
  offset, which is added to this key's scalar mod N.
  """
  @spec derive_child(t(), BSV.PublicKey.t(), String.t()) :: {:ok, t()} | {:error, String.t()}
  def derive_child(%__MODULE__{raw: raw} = key, %BSV.PublicKey{} = pub_key, invoice_number) do
    with {:ok, shared_secret} <- derive_shared_secret(key, pub_key) do
      shared_compressed = shared_secret.point
      # sha256_hmac(data, key) — key is shared secret, data is invoice number
      hmac = BSV.Crypto.sha256_hmac(invoice_number, shared_compressed)
      # Add HMAC scalar to current scalar mod N
      current = :binary.decode_unsigned(raw, :big)
      offset = :binary.decode_unsigned(hmac, :big)
      new_scalar = rem(current + offset, @n)

      if new_scalar == 0 do
        {:error, "derived child key is zero (invalid); use a different invoice number"}
      else
        new_bytes = :binary.encode_unsigned(new_scalar, :big) |> pad_to(32)
        from_bytes(new_bytes)
      end
    end
  end

  defp pad_to(bin, len) when byte_size(bin) >= len, do: bin
  defp pad_to(bin, len), do: :binary.copy(<<0>>, len - byte_size(bin)) <> bin

  defp normalize_low_s(der) do
    case der do
      <<0x30, _total_len::8, 0x02, r_len::8, r::binary-size(r_len), 0x02, s_len::8,
        s::binary-size(s_len)>> ->
        s_int = :binary.decode_unsigned(s, :big)

        if s_int > @n_half do
          new_s_int = @n - s_int
          new_s = :binary.encode_unsigned(new_s_int, :big)
          new_s = if :binary.first(new_s) >= 0x80, do: <<0x00, new_s::binary>>, else: new_s
          new_s_len = byte_size(new_s)
          r_part = <<0x02, r_len::8, r::binary>>
          s_part = <<0x02, new_s_len::8, new_s::binary>>
          total = byte_size(r_part) + byte_size(s_part)
          <<0x30, total::8, r_part::binary, s_part::binary>>
        else
          der
        end

      _ ->
        # Non-standard DER encoding; return as-is rather than crash
        der
    end
  end
end
