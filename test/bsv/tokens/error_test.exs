defmodule BSV.Tokens.ErrorTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Error

  test "invalid_scheme" do
    err = Error.invalid_scheme("bad format")
    assert err.type == :invalid_scheme
    assert err.message =~ "bad format"
    assert is_exception(err)
  end

  test "amount_mismatch" do
    err = Error.amount_mismatch(100, 50)
    assert err.type == :amount_mismatch
    assert err.message =~ "100"
    assert err.message =~ "50"
  end

  test "invalid_script" do
    err = Error.invalid_script("corrupted")
    assert err.type == :invalid_script
    assert err.message =~ "corrupted"
  end

  test "invalid_destination" do
    err = Error.invalid_destination("bad address")
    assert err.type == :invalid_destination
    assert err.message =~ "bad address"
  end

  test "invalid_authority" do
    err = Error.invalid_authority("unauthorized")
    assert err.type == :invalid_authority
    assert err.message =~ "unauthorized"
  end

  test "insufficient_funds" do
    err = Error.insufficient_funds(1000, 500)
    assert err.type == :insufficient_funds
    assert err.message =~ "1000"
    assert err.message =~ "500"
  end

  test "exception message" do
    err = Error.invalid_scheme("test")
    assert Exception.message(err) =~ "invalid scheme"
  end
end
