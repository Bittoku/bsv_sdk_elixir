defmodule BSV.Tokens.PaymentResolveTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey}
  alias BSV.Tokens.{Payment, SigningKey}
  alias BSV.Transaction.P2MPKH

  describe "resolve_signing_key/1" do
    test "returns signing_key directly when present" do
      key = PrivateKey.generate()
      sk = SigningKey.single(key)

      payment = %Payment{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 1000,
        signing_key: sk
      }

      assert ^sk = Payment.resolve_signing_key(payment)
    end

    test "returns multi signing_key directly when present" do
      {keys, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      sk = SigningKey.multi(Enum.take(keys, 2), ms)

      payment = %Payment{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 1000,
        signing_key: sk
      }

      result = Payment.resolve_signing_key(payment)
      assert {:multi, returned_keys, returned_ms} = result
      assert length(returned_keys) == 2
      assert returned_ms.threshold == 2
      assert length(returned_ms.public_keys) == 3
    end

    test "wraps private_key as {:single, key} when signing_key is nil" do
      key = PrivateKey.generate()

      payment = %Payment{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 1000,
        private_key: key,
        signing_key: nil
      }

      result = Payment.resolve_signing_key(payment)
      assert {:single, ^key} = result
    end

    test "prefers signing_key over private_key when both present" do
      key1 = PrivateKey.generate()
      key2 = PrivateKey.generate()
      sk = SigningKey.single(key1)

      payment = %Payment{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 1000,
        signing_key: sk,
        private_key: key2
      }

      assert {:single, ^key1} = Payment.resolve_signing_key(payment)
    end

    test "raises when neither signing_key nor private_key is set" do
      payment = %Payment{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 1000
      }

      assert_raise RuntimeError, ~r/Payment has neither/, fn ->
        Payment.resolve_signing_key(payment)
      end
    end
  end

  defp gen_keys(n) do
    privs = for _ <- 1..n, do: PrivateKey.generate()

    pubs =
      Enum.map(privs, fn k ->
        PrivateKey.to_public_key(k) |> PublicKey.compress() |> Map.get(:point)
      end)

    {privs, pubs}
  end
end
