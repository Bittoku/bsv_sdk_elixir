defmodule BSV.Wallet.ErrorTest do
  use ExUnit.Case, async: true

  alias BSV.Wallet.Error

  test "creates error with message" do
    err = %Error{message: "invalid key"}
    assert err.message == "invalid key"
  end

  test "is an exception" do
    assert is_exception(%Error{message: "test"})
  end

  test "message/1 returns the message" do
    err = %Error{message: "bad wallet"}
    assert Exception.message(err) == "bad wallet"
  end
end
