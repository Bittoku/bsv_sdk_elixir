defmodule BSV.Auth.NonceTest do
  use ExUnit.Case, async: true

  alias BSV.PrivateKey
  alias BSV.Auth.Nonce
  alias BSV.Wallet.ProtoWallet
  alias BSV.Wallet.Types.Counterparty

  defp make_key(val) do
    {:ok, pk} = PrivateKey.from_bytes(<<0::248, val::8>>)
    pk
  end

  defp wallet, do: ProtoWallet.from_private_key(make_key(42))
  defp cp, do: %Counterparty{type: :self}

  describe "create/verify" do
    test "round-trip" do
      w = wallet()
      c = cp()
      {:ok, nonce} = Nonce.create(w, c)
      assert is_binary(nonce)
      {:ok, valid} = Nonce.verify(nonce, w, c)
      assert valid == true
    end

    test "tampered nonce fails" do
      w = wallet()
      c = cp()
      {:ok, nonce} = Nonce.create(w, c)
      {:ok, bytes} = Base.decode64(nonce)
      tampered = Base.encode64(<<0>> <> binary_part(bytes, 1, byte_size(bytes) - 1))
      {:ok, valid} = Nonce.verify(tampered, w, c)
      assert valid == false
    end

    test "invalid base64 fails" do
      w = wallet()
      assert {:error, _} = Nonce.verify("not-valid-base64!!!", w, cp())
    end

    test "wrong length fails" do
      w = wallet()
      short = Base.encode64(:crypto.strong_rand_bytes(10))
      assert {:error, _} = Nonce.verify(short, w, cp())
    end
  end
end
