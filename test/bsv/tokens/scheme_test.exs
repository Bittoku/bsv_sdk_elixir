defmodule BSV.Tokens.SchemeTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.{Scheme, Authority, TokenId}

  defp sample_scheme do
    %Scheme{
      name: "Test Token",
      token_id: TokenId.from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
      symbol: "TST",
      satoshis_per_token: 1000,
      freeze: true,
      confiscation: false,
      is_divisible: true,
      authority: %Authority{
        m: 2,
        public_keys: [
          "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc",
          "03a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc"
        ]
      }
    }
  end

  test "JSON roundtrip" do
    scheme = sample_scheme()
    {:ok, json} = Scheme.to_json(scheme)
    {:ok, restored} = Scheme.from_json(json)
    assert restored.name == scheme.name
    assert restored.symbol == scheme.symbol
    assert restored.satoshis_per_token == scheme.satoshis_per_token
    assert restored.freeze == scheme.freeze
    assert restored.authority.m == scheme.authority.m
    assert length(restored.authority.public_keys) == 2
  end

  test "authority validate ok" do
    auth = %Authority{m: 1, public_keys: ["key1"]}
    assert :ok == Authority.validate(auth)
  end

  test "authority validate m zero" do
    auth = %Authority{m: 0, public_keys: ["key1"]}
    assert {:error, _} = Authority.validate(auth)
  end

  test "authority validate m exceeds keys" do
    auth = %Authority{m: 3, public_keys: ["key1", "key2"]}
    assert {:error, _} = Authority.validate(auth)
  end

  test "authority validate empty keys" do
    auth = %Authority{m: 1, public_keys: []}
    assert {:error, _} = Authority.validate(auth)
  end
end
