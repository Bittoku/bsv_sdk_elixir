defmodule BSV.ARC.ErrorTest do
  use ExUnit.Case, async: true

  alias BSV.ARC.Error

  test "creates error with all fields" do
    err = %Error{type: :http, message: "connection failed", code: 500}
    assert err.type == :http
    assert err.message == "connection failed"
    assert err.code == 500
  end

  test "message/1 returns the message" do
    err = %Error{type: :rejected, message: "tx rejected", code: 400}
    assert Exception.message(err) == "tx rejected"
  end

  test "is an exception" do
    err = %Error{type: :timeout, message: "timed out", code: nil}
    assert is_exception(err)
  end

  test "different error types" do
    for type <- [:http, :serialization, :rejected, :timeout] do
      err = %Error{type: type, message: "test", code: nil}
      assert err.type == type
    end
  end

  test "can be raised and rescued" do
    assert_raise Error, "boom", fn ->
      raise Error, type: :http, message: "boom", code: 500
    end
  end
end
