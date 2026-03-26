defmodule BSV.Tokens.OwnerAddressTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.OwnerAddress
  alias BSV.Transaction.P2MPKH
  alias BSV.{Crypto, PrivateKey, PublicKey}

  describe "from_address/1" do
    test "wraps an address string" do
      assert {:address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"} =
               OwnerAddress.from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    end
  end

  describe "from_mpkh/1" do
    test "wraps 20 bytes" do
      mpkh = :crypto.strong_rand_bytes(20)
      assert {:mpkh, ^mpkh} = OwnerAddress.from_mpkh(mpkh)
    end
  end

  describe "from_multisig/1" do
    test "computes MPKH from multisig" do
      pubs = for _ <- 1..3, do: PrivateKey.generate() |> PrivateKey.to_public_key() |> PublicKey.compress() |> Map.get(:point)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      oa = OwnerAddress.from_multisig(ms)
      assert {:mpkh, mpkh} = oa
      assert mpkh == P2MPKH.mpkh(ms)
    end
  end

  describe "hash/1" do
    test "returns MPKH for mpkh variant" do
      mpkh = :crypto.strong_rand_bytes(20)
      assert {:ok, ^mpkh} = OwnerAddress.hash({:mpkh, mpkh})
    end

    test "returns PKH for valid address" do
      key = PrivateKey.generate()
      pkh = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point) |> Crypto.hash160()
      addr = BSV.Base58.check_encode(pkh, 0x00)
      assert {:ok, ^pkh} = OwnerAddress.hash({:address, addr})
    end

    test "errors for invalid address" do
      assert {:error, :invalid_address} = OwnerAddress.hash({:address, "not_a_real_address"})
    end
  end
end
