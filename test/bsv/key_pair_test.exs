defmodule BSV.KeyPairTest do
  use ExUnit.Case, async: true

  alias BSV.{KeyPair, PrivateKey, PublicKey}

  test "new/0 generates a valid key pair" do
    kp = KeyPair.new()
    assert %KeyPair{} = kp
    assert %PrivateKey{} = kp.privkey
    assert %PublicKey{} = kp.pubkey
  end

  test "from_private_key/1 derives correct pubkey" do
    privkey = PrivateKey.generate()
    kp = KeyPair.from_private_key(privkey)
    assert kp.privkey == privkey
    assert kp.pubkey == PrivateKey.to_public_key(privkey)
  end

  test "pubkey_bytes/1 returns 33-byte compressed key" do
    kp = KeyPair.new()
    bytes = KeyPair.pubkey_bytes(kp)
    assert byte_size(bytes) == 33
    assert <<prefix, _::binary>> = bytes
    assert prefix in [0x02, 0x03]
  end

  test "pubkey_hash/1 returns 20-byte hash" do
    kp = KeyPair.new()
    hash = KeyPair.pubkey_hash(kp)
    assert byte_size(hash) == 20
  end

  test "two new key pairs are distinct" do
    kp1 = KeyPair.new()
    kp2 = KeyPair.new()
    assert kp1.privkey.raw != kp2.privkey.raw
  end
end
