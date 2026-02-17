defmodule BSV.JungleBus.ErrorTest do
  use ExUnit.Case, async: true

  alias BSV.JungleBus.Error

  test "creates error with all fields" do
    err = %Error{type: :http, message: "connection failed", status_code: 500}
    assert err.type == :http
    assert err.message == "connection failed"
    assert err.status_code == 500
  end

  test "message/1 returns the message" do
    err = %Error{type: :not_found, message: "not found", status_code: 404}
    assert Exception.message(err) == "not found"
  end

  test "is an exception" do
    assert is_exception(%Error{type: :server_error, message: "err", status_code: nil})
  end

  test "different error types" do
    for type <- [:http, :serialization, :server_error, :not_found] do
      err = %Error{type: type, message: "test", status_code: nil}
      assert err.type == type
    end
  end

  test "can be raised and rescued" do
    assert_raise Error, "boom", fn ->
      raise Error, type: :http, message: "boom", status_code: 500
    end
  end
end
