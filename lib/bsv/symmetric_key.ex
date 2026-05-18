defmodule BSV.SymmetricKey do
  @moduledoc """
  AES-256-GCM symmetric encryption.

  ## Migration Notice (v0.2)

  The IV size was changed from 32 bytes to the standard 12 bytes for GCM.
  Decryption automatically detects the IV size of the ciphertext:

  - New ciphertexts use 12-byte IVs (standard, secure)
  - Legacy ciphertexts with 32-byte IVs are still decryptable

  Encryption always uses the new 12-byte IV format. To migrate legacy data,
  decrypt with the old key and re-encrypt — the new format is used automatically.
  """

  @enforce_keys [:raw]
  defstruct [:raw]

  @type t :: %__MODULE__{raw: <<_::256>>}

  @iv_size 12
  @legacy_iv_size 32
  @tag_size 16

  # Default AAD: binds ciphertexts to this SDK's encryption context.
  # Prevents cross-protocol ciphertext transplantation.
  @default_aad "BSV_SDK_SYMMETRIC_V1"

  @doc "Create a new SymmetricKey from a 32-byte binary."
  @spec new(<<_::256>>) :: t()
  def new(<<raw::binary-size(32)>>), do: %__MODULE__{raw: raw}

  @doc "Get the raw key bytes."
  @spec to_bytes(t()) :: <<_::256>>
  def to_bytes(%__MODULE__{raw: raw}), do: raw

  @doc """
  Encrypt plaintext with a 32-byte key using AES-256-GCM (12-byte IV).

  Includes the SDK default AAD context to bind the ciphertext to this
  encryption protocol (prevents cross-protocol ciphertext transplantation).
  Use `encrypt/3` to supply custom Additional Authenticated Data.
  """
  @spec encrypt(<<_::256>> | t(), binary()) :: {:ok, binary()}
  def encrypt(key, plaintext), do: encrypt(key, plaintext, @default_aad)

  @doc "Encrypt with explicit Additional Authenticated Data (AAD)."
  @spec encrypt(<<_::256>> | t(), binary(), binary()) :: {:ok, binary()}
  def encrypt(%__MODULE__{raw: key}, plaintext, aad), do: encrypt(key, plaintext, aad)

  def encrypt(<<key::binary-size(32)>>, plaintext, aad) when is_binary(aad) do
    iv = :crypto.strong_rand_bytes(@iv_size)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, aad, @tag_size, true)

    {:ok, iv <> ciphertext <> tag}
  end

  @doc """
  Decrypt ciphertext with a 32-byte key using AES-256-GCM.

  Uses the SDK default AAD for decryption. For legacy ciphertexts encrypted
  with empty AAD, use `decrypt/4` with `<<>>` as the AAD parameter.

  Automatically detects IV size: tries 12-byte (current) first, then
  falls back to 32-byte (legacy) for backward compatibility.
  """
  @spec decrypt(<<_::256>> | t(), binary()) :: {:ok, binary()} | {:error, :decrypt_failed}
  def decrypt(key, encrypted), do: decrypt(key, encrypted, @default_aad)

  @doc "Decrypt with explicit Additional Authenticated Data (AAD)."
  @spec decrypt(<<_::256>> | t(), binary(), binary()) :: {:ok, binary()} | {:error, :decrypt_failed}
  def decrypt(%__MODULE__{raw: key}, encrypted, aad), do: decrypt(key, encrypted, aad)

  def decrypt(<<key::binary-size(32)>>, encrypted, aad) when is_binary(aad) do
    # Try standard 12-byte IV first
    case decrypt_with_iv_size(key, encrypted, @iv_size, aad) do
      {:ok, _} = result ->
        result

      _error ->
        # Fall back to legacy 32-byte IV
        case decrypt_with_iv_size(key, encrypted, @legacy_iv_size, aad) do
          {:ok, _} = result -> result
          _ -> {:error, :decrypt_failed}
        end
    end
  end

  defp decrypt_with_iv_size(key, encrypted, iv_size, aad) when byte_size(encrypted) >= iv_size + @tag_size do
    ct_len = byte_size(encrypted) - iv_size - @tag_size

    <<iv::binary-size(iv_size), ciphertext::binary-size(ct_len), tag::binary-size(@tag_size)>> =
      encrypted

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, tag, false) do
      :error -> {:error, :decrypt_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  defp decrypt_with_iv_size(_key, _encrypted, _iv_size, _aad), do: {:error, :too_short}
end
