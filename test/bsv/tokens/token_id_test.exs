defmodule BSV.Tokens.TokenIdTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.TokenId

  test "from_string stores address and zeroed pkh" do
    tid = TokenId.from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert tid.address_string == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert tid.pkh == <<0::160>>
  end

  test "from_pkh creates hex address" do
    pkh = :binary.copy(<<0xAA>>, 20)
    tid = TokenId.from_pkh(pkh)
    assert tid.pkh == pkh
    assert tid.address_string == String.duplicate("aa", 20)
  end

  test "from_address stores both" do
    pkh = :binary.copy(<<0xBB>>, 20)
    tid = TokenId.from_address("1TestAddr", pkh)
    assert tid.address_string == "1TestAddr"
    assert tid.pkh == pkh
  end

  test "to_string returns address" do
    tid = TokenId.from_string("1TestAddr")
    assert "#{tid}" == "1TestAddr"
  end

  test "JSON encoding" do
    pkh = :binary.copy(<<0xCC>>, 20)
    tid = TokenId.from_address("1Addr", pkh)
    json = Jason.encode!(tid)
    decoded = Jason.decode!(json)
    assert decoded["address_string"] == "1Addr"
    assert decoded["pkh"] == String.duplicate("cc", 20)
  end
end
