defmodule BSV.SymmetricKey do
  @moduledoc """
  AES-256-GCM symmetric encryption.
  """

  @enforce_keys [:raw]
  defstruct [:raw]

  @type t :: %__MODULE__{raw: <<_::256>>}

  @iv_size 32
  @tag_size 16

  @doc "Create a new SymmetricKey from a 32-byte binary."
  @spec new(<<_::256>>) :: t()
  def new(<<raw::binary-size(32)>>), do: %__MODULE__{raw: raw}

  @doc "Get the raw key bytes."
  @spec to_bytes(t()) :: <<_::256>>
  def to_bytes(%__MODULE__{raw: raw}), do: raw

  @doc "Encrypt plaintext with a 32-byte key using AES-256-GCM."
  @spec encrypt(<<_::256>> | t(), binary()) :: {:ok, binary()}
  def encrypt(%__MODULE__{raw: key}, plaintext), do: encrypt(key, plaintext)

  def encrypt(<<key::binary-size(32)>>, plaintext) do
    iv = :crypto.strong_rand_bytes(@iv_size)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, <<>>, @tag_size, true)

    {:ok, iv <> ciphertext <> tag}
  end

  @doc "Decrypt ciphertext with a 32-byte key using AES-256-GCM."
  @spec decrypt(<<_::256>> | t(), binary()) :: {:ok, binary()} | {:error, :decrypt_failed}
  def decrypt(%__MODULE__{raw: key}, encrypted), do: decrypt(key, encrypted)

  def decrypt(<<key::binary-size(32)>>, encrypted)
      when byte_size(encrypted) >= @iv_size + @tag_size do
    ct_len = byte_size(encrypted) - @iv_size - @tag_size

    <<iv::binary-size(@iv_size), ciphertext::binary-size(ct_len), tag::binary-size(@tag_size)>> =
      encrypted

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, <<>>, tag, false) do
      :error -> {:error, :decrypt_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  def decrypt(<<_::binary-size(32)>>, _), do: {:error, :decrypt_failed}
end
