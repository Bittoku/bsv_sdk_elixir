defmodule BSV.Tokens.SigningKeyTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.SigningKey
  alias BSV.Transaction.P2MPKH
  alias BSV.{Crypto, PrivateKey, PublicKey}

  defp gen_keys(n) do
    privs = for _ <- 1..n, do: PrivateKey.generate()
    pubs = Enum.map(privs, fn k -> PrivateKey.to_public_key(k) |> PublicKey.compress() |> Map.get(:point) end)
    {privs, pubs}
  end

  describe "single/1" do
    test "wraps a private key" do
      key = PrivateKey.generate()
      assert {:single, ^key} = SigningKey.single(key)
    end
  end

  describe "multi/2" do
    test "wraps keys and multisig" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      sk = SigningKey.multi(Enum.take(privs, 2), ms)
      assert {:multi, _, ^ms} = sk
    end
  end

  describe "wrap/1" do
    test "wraps PrivateKey" do
      key = PrivateKey.generate()
      assert {:single, ^key} = SigningKey.wrap(key)
    end

    test "passes through existing signing keys" do
      key = PrivateKey.generate()
      sk = SigningKey.single(key)
      assert ^sk = SigningKey.wrap(sk)
    end
  end

  describe "hash160/1" do
    test "single returns pubkey hash" do
      key = PrivateKey.generate()
      expected = PrivateKey.to_public_key(key) |> PublicKey.compress() |> Map.get(:point) |> Crypto.hash160()
      assert SigningKey.hash160(SigningKey.single(key)) == expected
    end

    test "multi returns MPKH" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      expected = P2MPKH.mpkh(ms)
      sk = SigningKey.multi(Enum.take(privs, 2), ms)
      assert SigningKey.hash160(sk) == expected
    end
  end

  describe "multi?/1" do
    test "false for single" do
      key = PrivateKey.generate()
      refute SigningKey.multi?(SigningKey.single(key))
    end

    test "true for multi" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      assert SigningKey.multi?(SigningKey.multi([hd(privs)], ms))
    end
  end
end
