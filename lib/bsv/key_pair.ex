defmodule BSV.KeyPair do
  @moduledoc """
  Convenience struct pairing a `BSV.PrivateKey` with its corresponding `BSV.PublicKey`.

  ## Example

      kp = BSV.KeyPair.new()
      kp.privkey  #=> %BSV.PrivateKey{...}
      kp.pubkey   #=> %BSV.PublicKey{...}

      # From an existing private key
      kp = BSV.KeyPair.from_private_key(privkey)
  """

  alias BSV.{PrivateKey, PublicKey}

  @enforce_keys [:privkey, :pubkey]
  defstruct [:privkey, :pubkey]

  @type t :: %__MODULE__{
          privkey: PrivateKey.t(),
          pubkey: PublicKey.t()
        }

  @doc "Generate a new random key pair."
  @spec new() :: t()
  def new do
    privkey = PrivateKey.generate()
    from_private_key(privkey)
  end

  @doc "Build a key pair from an existing private key."
  @spec from_private_key(PrivateKey.t()) :: t()
  def from_private_key(%PrivateKey{} = privkey) do
    %__MODULE__{
      privkey: privkey,
      pubkey: PrivateKey.to_public_key(privkey)
    }
  end

  @doc "Return the compressed public key bytes (33 bytes)."
  @spec pubkey_bytes(t()) :: binary()
  def pubkey_bytes(%__MODULE__{pubkey: pubkey}) do
    PublicKey.compress(pubkey).point
  end

  @doc "Return the 20-byte public key hash (HASH160)."
  @spec pubkey_hash(t()) :: <<_::160>>
  def pubkey_hash(%__MODULE__{} = kp) do
    BSV.Crypto.hash160(pubkey_bytes(kp))
  end
end
