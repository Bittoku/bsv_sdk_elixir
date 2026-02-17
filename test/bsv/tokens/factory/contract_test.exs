defmodule BSV.Tokens.Factory.ContractTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Crypto}
  alias BSV.Tokens.Factory.Contract
  alias BSV.Tokens.{Scheme, Authority, TokenId}

  defp test_key do
    PrivateKey.generate()
  end

  defp p2pkh_script(key) do
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    address = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, script} = BSV.Script.Address.to_script(address)
    script
  end

  defp test_scheme do
    %Scheme{
      name: "Test",
      token_id: TokenId.from_string("1Test"),
      symbol: "TST",
      satoshis_per_token: 1,
      freeze: false,
      confiscation: false,
      is_divisible: true,
      authority: %Authority{m: 1, public_keys: ["02abcdef"]}
    }
  end

  test "build contract tx structure" do
    key = test_key()

    config = %{
      scheme: test_scheme(),
      funding_txid: :binary.copy(<<0xAA>>, 32),
      funding_vout: 0,
      funding_satoshis: 100_000,
      funding_locking_script: p2pkh_script(key),
      funding_private_key: key,
      contract_satoshis: 10_000,
      fee_rate: 500
    }

    {:ok, tx} = Contract.build_contract_tx(config)
    assert length(tx.inputs) == 1
    assert length(tx.outputs) >= 2
    assert Enum.at(tx.outputs, 0).satoshis == 10_000
    assert Enum.at(tx.outputs, 1).satoshis == 0
    assert tx.inputs |> hd() |> Map.get(:unlocking_script) != nil
  end

  test "insufficient funds" do
    key = test_key()

    config = %{
      scheme: test_scheme(),
      funding_txid: :binary.copy(<<0xAA>>, 32),
      funding_vout: 0,
      funding_satoshis: 100,
      funding_locking_script: p2pkh_script(key),
      funding_private_key: key,
      contract_satoshis: 10_000,
      fee_rate: 500
    }

    assert {:error, _} = Contract.build_contract_tx(config)
  end
end
