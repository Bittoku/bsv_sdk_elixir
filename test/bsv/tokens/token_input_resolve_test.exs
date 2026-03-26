defmodule BSV.Tokens.TokenInputResolveTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey}
  alias BSV.Tokens.{TokenInput, SigningKey}
  alias BSV.Transaction.P2MPKH

  describe "resolve_signing_key/1" do
    test "returns signing_key directly when present" do
      key = PrivateKey.generate()
      sk = SigningKey.single(key)

      ti = %TokenInput{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 500,
        signing_key: sk
      }

      assert ^sk = TokenInput.resolve_signing_key(ti)
    end

    test "returns multi signing_key directly when present" do
      {keys, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      sk = SigningKey.multi(Enum.take(keys, 2), ms)

      ti = %TokenInput{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 500,
        signing_key: sk
      }

      result = TokenInput.resolve_signing_key(ti)
      assert {:multi, returned_keys, returned_ms} = result
      assert length(returned_keys) == 2
      assert returned_ms.threshold == 2
    end

    test "wraps private_key as {:single, key} when signing_key is nil" do
      key = PrivateKey.generate()

      ti = %TokenInput{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 500,
        private_key: key,
        signing_key: nil
      }

      result = TokenInput.resolve_signing_key(ti)
      assert {:single, ^key} = result
    end

    test "prefers signing_key over private_key when both present" do
      key1 = PrivateKey.generate()
      key2 = PrivateKey.generate()
      sk = SigningKey.single(key1)

      ti = %TokenInput{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 500,
        signing_key: sk,
        private_key: key2
      }

      assert {:single, ^key1} = TokenInput.resolve_signing_key(ti)
    end

    test "raises when neither signing_key nor private_key is set" do
      ti = %TokenInput{
        txid: <<0::256>>,
        vout: 0,
        satoshis: 500
      }

      assert_raise RuntimeError, ~r/TokenInput has neither/, fn ->
        TokenInput.resolve_signing_key(ti)
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
