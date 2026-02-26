defmodule BSV.Contract.P2RPHTest do
  use ExUnit.Case, async: true

  alias BSV.{Contract, Crypto}
  alias BSV.Contract.P2RPH

  describe "generate_k/0 and get_r/1" do
    test "generates a 32-byte K value" do
      k = P2RPH.generate_k()
      assert byte_size(k) == 32
    end

    test "get_r returns R value from K" do
      k = P2RPH.generate_k()
      r = P2RPH.get_r(k)
      assert is_binary(r)
      # R is 32 or 33 bytes (33 if high bit set, leading 0x00 prepended)
      assert byte_size(r) in [32, 33]
    end

    test "same K always produces same R" do
      k = P2RPH.generate_k()
      r1 = P2RPH.get_r(k)
      r2 = P2RPH.get_r(k)
      assert r1 == r2
    end

    test "different K values produce different R values" do
      k1 = P2RPH.generate_k()
      k2 = P2RPH.generate_k()
      assert P2RPH.get_r(k1) != P2RPH.get_r(k2)
    end
  end

  describe "locking script" do
    test "with r value produces correct script structure" do
      k = P2RPH.generate_k()
      r = P2RPH.get_r(k)

      contract = P2RPH.lock(1000, %{r: r})
      script = Contract.to_script(contract)

      # Check structure: OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
      #   OP_HASH160 <r_hash> OP_EQUALVERIFY OP_TUCK OP_CHECKSIGVERIFY OP_CHECKSIG
      assert length(script.chunks) == 15

      # First chunk should be OP_OVER
      assert hd(script.chunks) == {:op, 0x78}

      # Should contain HASH160 of r
      r_hash = Crypto.hash160(r)
      assert {:data, ^r_hash} = Enum.at(script.chunks, 10)

      # Last two should be OP_CHECKSIGVERIFY and OP_CHECKSIG
      assert Enum.at(script.chunks, 13) == {:op, 0xAD}
      assert Enum.at(script.chunks, 14) == {:op, 0xAC}
    end

    test "with r_hash directly" do
      r_hash = :crypto.strong_rand_bytes(20)

      contract = P2RPH.lock(1000, %{r_hash: r_hash})
      script = Contract.to_script(contract)

      assert {:data, ^r_hash} = Enum.at(script.chunks, 10)
    end

    test "compiles to binary" do
      k = P2RPH.generate_k()
      r = P2RPH.get_r(k)
      contract = P2RPH.lock(1000, %{r: r})
      bin = Contract.to_binary(contract)
      assert is_binary(bin)
      assert byte_size(bin) > 0
    end
  end

  describe "unlocking script" do
    test "produces 3 pushdata elements (sig, k-sig, pubkey)" do
      privkey = BSV.PrivateKey.generate()
      pubkey = BSV.PrivateKey.to_public_key(privkey) |> BSV.PublicKey.compress()
      k = P2RPH.generate_k()

      contract = P2RPH.unlock(%{}, %{
        privkey: privkey,
        k: k,
        pubkey: pubkey.point
      })

      script = Contract.to_script(contract)
      # Should have 3 chunks: sig placeholder, k-sig placeholder, pubkey
      assert length(script.chunks) == 3

      # Without context, first two are zero placeholders
      [{:data, sig1}, {:data, sig2}, {:data, pk}] = script.chunks
      assert sig1 == <<0::568>>
      assert sig2 == <<0::568>>
      assert pk == pubkey.point
    end
  end
end
