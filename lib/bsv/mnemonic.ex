defmodule BSV.Mnemonic do
  @moduledoc """
  BIP-39 mnemonic phrase generation and seed derivation.

  A mnemonic is a human-readable representation of entropy used to create
  deterministic wallets. Words are drawn from a standard 2048-word list and
  include a built-in checksum.

  **Note:** The wordlist language is fixed at compile time and defaults to English.
  Non-English BIP-39 wordlists are not currently supported.

  ## Examples

      iex> mnemonic = BSV.Mnemonic.generate()
      iex> is_binary(mnemonic) and length(String.split(mnemonic)) == 12
      true

      iex> seed = BSV.Mnemonic.to_seed("abandon " |> String.duplicate(11) |> Kernel.<>("about") |> String.trim())
      iex> byte_size(seed) == 64
      true
  """

  @typedoc "Mnemonic phrase (space-separated words)"
  @type t :: String.t()

  @typedoc "Binary seed derived from mnemonic"
  @type seed :: <<_::512>>

  @typedoc "Entropy bit length"
  @type entropy_bits :: 128 | 160 | 192 | 224 | 256

  @allowed_lengths [128, 160, 192, 224, 256]
  @pbkdf2_rounds 2048

  @lang Application.compile_env(:bsv_sdk, :bip39_lang, "en")

  @wordlist :code.priv_dir(:bsv_sdk)
            |> Path.join("bip39/#{@lang}.txt")
            |> File.stream!()
            |> Stream.map(&String.trim/1)
            |> Enum.to_list()

  @doc """
  Generate a random mnemonic phrase.

  ## Options

  - `entropy_bits` — one of 128 (12 words), 160 (15), 192 (18), 224 (21), 256 (24).
    Defaults to 128.
  """
  @spec generate(entropy_bits()) :: t()
  def generate(entropy_bits \\ 128) when entropy_bits in @allowed_lengths do
    entropy_bits
    |> div(8)
    |> :crypto.strong_rand_bytes()
    |> from_entropy()
  end

  @doc """
  Create a mnemonic phrase from raw entropy bytes.

  The entropy must be 16, 20, 24, 28, or 32 bytes (128–256 bits).
  """
  @spec from_entropy(binary()) :: t()
  def from_entropy(entropy)
      when is_binary(entropy) and bit_size(entropy) in @allowed_lengths do
    checksummed = <<entropy::bits, checksum(entropy)::bits>>
    chunks = for <<chunk::11 <- checksummed>>, do: Enum.at(@wordlist, chunk)
    Enum.join(chunks, " ")
  end

  @doc """
  Extract the raw entropy bytes from a mnemonic phrase.
  """
  @spec to_entropy(t()) :: binary()
  def to_entropy(mnemonic) when is_binary(mnemonic) do
    indices = mnemonic |> String.split() |> Enum.map(&word_index/1)
    bits = for i <- indices, into: <<>>, do: <<i::11>>
    entropy_bits = div(bit_size(bits) * 32, 33)
    <<entropy::bits-size(entropy_bits), _::bits>> = bits
    entropy
  end

  @doc """
  Derive a 512-bit seed from a mnemonic phrase using PBKDF2-HMAC-SHA512.

  ## Options

  - `:passphrase` — optional passphrase (BIP-39 "25th word"). Default `""`.
  - `:encoding` — `:hex` or `:base64` to encode the result. Default `nil` (raw binary).
  """
  @spec to_seed(t(), keyword()) :: seed() | String.t()
  def to_seed(mnemonic, opts \\ []) when is_binary(mnemonic) do
    passphrase = Keyword.get(opts, :passphrase, "")
    encoding = Keyword.get(opts, :encoding)
    salt = "mnemonic" <> passphrase

    seed = pbkdf2_sha512(mnemonic, salt, @pbkdf2_rounds)
    encode(seed, encoding)
  end

  @doc """
  Validate a mnemonic phrase (correct word count, valid words, valid checksum).
  """
  @spec valid?(t()) :: boolean()
  def valid?(mnemonic) when is_binary(mnemonic) do
    words = String.split(mnemonic)
    word_count = length(words)

    word_count in [12, 15, 18, 21, 24] and
      Enum.all?(words, &(&1 in @wordlist)) and
      valid_checksum?(mnemonic)
  rescue
    _ -> false
  end

  @doc false
  @spec wordlist() :: [String.t()]
  def wordlist, do: @wordlist

  # -- Private --

  defp checksum(entropy) do
    cs_bits = div(bit_size(entropy), 32)
    <<cs::bits-size(cs_bits), _::bits>> = BSV.Crypto.sha256(entropy)
    cs
  end

  defp valid_checksum?(mnemonic) do
    entropy = to_entropy(mnemonic)
    # Rebuild and compare
    rebuilt = from_entropy(entropy)
    rebuilt == mnemonic
  end

  defp word_index(word) do
    case Enum.find_index(@wordlist, &(&1 == word)) do
      nil -> raise ArgumentError, "unknown BIP-39 word: #{word}"
      idx -> idx
    end
  end

  defp pbkdf2_sha512(password, salt, rounds) do
    initial = :crypto.mac(:hmac, :sha512, password, <<salt::binary, 1::integer-32>>)
    iterate(password, 1, initial, initial, rounds)
  end

  defp iterate(_password, round, _prev, result, rounds) when round == rounds, do: result

  defp iterate(password, round, prev, result, rounds) do
    next = :crypto.mac(:hmac, :sha512, password, prev)
    iterate(password, round + 1, next, :crypto.exor(next, result), rounds)
  end

  defp encode(data, :hex), do: Base.encode16(data, case: :lower)
  defp encode(data, :base64), do: Base.encode64(data)
  defp encode(data, _), do: data
end
