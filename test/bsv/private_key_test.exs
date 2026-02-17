defmodule BSV.PrivateKeyTest do
  use ExUnit.Case, async: true

  @known_wif "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
  @known_hex "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"

  test "generate produces valid key" do
    key = BSV.PrivateKey.generate()
    assert byte_size(key.raw) == 32
  end

  test "from_bytes validates" do
    assert {:ok, _} = BSV.PrivateKey.from_bytes(:crypto.strong_rand_bytes(32) |> ensure_valid())
    assert {:error, _} = BSV.PrivateKey.from_bytes(<<0::256>>)
    assert {:error, _} = BSV.PrivateKey.from_bytes(<<1, 2, 3>>)
  end

  test "known WIF uncompressed" do
    {:ok, key} = BSV.PrivateKey.from_wif(@known_wif)
    assert Base.encode16(key.raw, case: :lower) == @known_hex
  end

  test "WIF roundtrip compressed" do
    key = BSV.PrivateKey.generate()
    wif = BSV.PrivateKey.to_wif(key, compressed: true)
    assert {:ok, decoded} = BSV.PrivateKey.from_wif(wif)
    assert decoded.raw == key.raw
  end

  test "WIF roundtrip uncompressed" do
    key = BSV.PrivateKey.generate()
    wif = BSV.PrivateKey.to_wif(key, compressed: false)
    assert {:ok, decoded} = BSV.PrivateKey.from_wif(wif)
    assert decoded.raw == key.raw
  end

  test "sign and verify" do
    key = BSV.PrivateKey.generate()
    pubkey = BSV.PrivateKey.to_public_key(key)
    msg = BSV.Crypto.sha256("test message")
    {:ok, sig} = BSV.PrivateKey.sign(key, msg)
    assert BSV.PublicKey.verify(pubkey, msg, sig)
  end

  test "from_wif! raises on invalid" do
    assert_raise ArgumentError, fn -> BSV.PrivateKey.from_wif!("invalid") end
  end

  test "from_wif! success" do
    {:ok, key} = BSV.PrivateKey.from_wif(@known_wif)
    key2 = BSV.PrivateKey.from_wif!(@known_wif)
    assert key.raw == key2.raw
  end

  test "derive_shared_secret" do
    key1 = BSV.PrivateKey.generate()
    key2 = BSV.PrivateKey.generate()
    pub2 = BSV.PrivateKey.to_public_key(key2)
    pub1 = BSV.PrivateKey.to_public_key(key1)
    {:ok, secret1} = BSV.PrivateKey.derive_shared_secret(key1, pub2)
    {:ok, secret2} = BSV.PrivateKey.derive_shared_secret(key2, pub1)
    assert secret1 == secret2
  end

  test "derive_child" do
    key = BSV.PrivateKey.generate()
    pub = BSV.PrivateKey.to_public_key(key)
    {:ok, child} = BSV.PrivateKey.derive_child(key, pub, "1")
    assert byte_size(child.raw) == 32
  end

  defp ensure_valid(<<raw::binary-size(32)>>) do
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    val = :binary.decode_unsigned(raw, :big)
    if val > 0 and val < n, do: raw, else: <<0::248, 1::8>>
  end
end
