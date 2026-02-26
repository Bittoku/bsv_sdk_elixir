defmodule BSV.Crypto.ECDSATest do
  use ExUnit.Case, async: true

  alias BSV.Crypto.ECDSA

  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  @n_half div(@n, 2)

  @vectors [
    %{
      d: "0000000000000000000000000000000000000000000000000000000000000001",
      message: "Everything should be made as simple as possible, but not simpler.",
      expected_r: "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
      expected_s: "6f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
    },
    %{
      d: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      message: "Equations are more important to me, because politics is for the present, but an equation is something for eternity.",
      expected_r: "54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed",
      expected_s: "07082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5"
    },
    %{
      d: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      message: "Not only is the Universe stranger than we think, it is stranger than we can think.",
      expected_r: "ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd0",
      expected_s: "6fc95f5132e5ecfdc8e5e6e616cc77151455d46ed48f5589b7db7771a332b283"
    },
    %{
      d: "0000000000000000000000000000000000000000000000000000000000000001",
      message: "How wonderful that we have met with a paradox. Now we have some hope of making progress.",
      expected_r: "c0dafec8251f1d5010289d210232220b03202cba34ec11fec58b3e93a85b91d3",
      expected_s: "75afdc06b7d6322a590955bf264e7aaa155847f614d80078a90292fe205064d3"
    },
    %{
      d: "69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64",
      message: "Computer science is no more about computers than astronomy is about telescopes.",
      expected_r: "7186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d",
      expected_s: "0de0b38e06807e46bda1f1e293f4f6323e854c86d58abdd00c46c16441085df6"
    },
    %{
      d: "00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637",
      message: "...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not learning anywhere near enough",
      expected_r: "fbfe5076a15860ba8ed00e75e9bd22e05d230f02a936b653eb55b61c99dda487",
      expected_s: "0e68880ebb0050fe4312b1b1eb0899e1b82da89baa5b895f612619edf34cbd37"
    },
    %{
      d: "000000000000000000000000000000000000000000056916d0f9b31dc9b637f3",
      message: "The question of whether computers can think is like the question of whether submarines can swim.",
      expected_r: "cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf9",
      expected_s: "06ce643f5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef"
    }
  ]

  for {vector, idx} <- Enum.with_index(@vectors, 1) do
    @vector vector
    test "ECDSA signature vector #{idx}" do
      d = Base.decode16!(@vector.d, case: :lower)
      hash = :crypto.hash(:sha256, @vector.message)
      expected_r = String.to_integer(@vector.expected_r, 16)
      expected_s = String.to_integer(@vector.expected_s, 16)

      {:ok, der} = ECDSA.sign(d, hash)

      # Decode DER
      <<0x30, _len::8, 0x02, r_len::8, r_bin::binary-size(r_len),
        0x02, s_len::8, s_bin::binary-size(s_len)>> = der

      r = :binary.decode_unsigned(r_bin, :big)
      s = :binary.decode_unsigned(s_bin, :big)

      assert r == expected_r,
        "Vector #{unquote(idx)}: r mismatch. Expected #{@vector.expected_r}, got #{Integer.to_string(r, 16) |> String.downcase()}"
      assert s == expected_s,
        "Vector #{unquote(idx)}: s mismatch. Expected #{@vector.expected_s}, got #{Integer.to_string(s, 16) |> String.downcase()}"
    end
  end

  for {vector, idx} <- Enum.with_index(@vectors, 1) do
    @vector vector
    test "cross-validate with :crypto.verify vector #{idx}" do
      d = Base.decode16!(@vector.d, case: :lower)
      hash = :crypto.hash(:sha256, @vector.message)

      {:ok, der} = ECDSA.sign(d, hash)

      # Derive public key
      {pubkey, _} = :crypto.generate_key(:ecdh, :secp256k1, d)

      assert :crypto.verify(:ecdsa, :sha256, {:digest, hash}, der, [pubkey, :secp256k1])
    end
  end

  test "determinism: signing same hash 100 times produces identical output" do
    d = Base.decode16!("69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64", case: :lower)
    hash = :crypto.hash(:sha256, "test message")
    {:ok, sig1} = ECDSA.sign(d, hash)

    for _ <- 1..100 do
      {:ok, sig} = ECDSA.sign(d, hash)
      assert sig == sig1
    end
  end

  test "low-S normalization" do
    # All signatures should have s <= n/2
    for vector <- @vectors do
      d = Base.decode16!(vector.d, case: :lower)
      hash = :crypto.hash(:sha256, vector.message)
      {:ok, der} = ECDSA.sign(d, hash)

      <<0x30, _len::8, 0x02, r_len::8, _r::binary-size(r_len),
        0x02, s_len::8, s_bin::binary-size(s_len)>> = der

      s = :binary.decode_unsigned(s_bin, :big)
      assert s <= @n_half, "s value not normalized to low-S"
    end
  end

  test "property: random keys sign and verify" do
    for _ <- 1..50 do
      {pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1)
      # Ensure valid key
      <<d::unsigned-big-256>> = privkey
      if d > 0 and d < @n do
        hash = :crypto.strong_rand_bytes(32)
        {:ok, der} = ECDSA.sign(privkey, hash)
        assert :crypto.verify(:ecdsa, :sha256, {:digest, hash}, der, [pubkey, :secp256k1])
      end
    end
  end

  test "property: random keys deterministic" do
    for _ <- 1..50 do
      {_pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1)
      <<d::unsigned-big-256>> = privkey
      if d > 0 and d < @n do
        hash = :crypto.strong_rand_bytes(32)
        {:ok, sig1} = ECDSA.sign(privkey, hash)
        {:ok, sig2} = ECDSA.sign(privkey, hash)
        assert sig1 == sig2
      end
    end
  end
end
