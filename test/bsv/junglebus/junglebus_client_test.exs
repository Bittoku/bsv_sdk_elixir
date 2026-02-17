defmodule BSV.JungleBus.ClientTest do
  use ExUnit.Case, async: true

  alias BSV.JungleBus.{Client, Config}

  defp test_config(port) do
    %Config{
      server_url: "http://localhost:#{port}",
      token: "test-token",
      api_version: "v1"
    }
  end

  test "get transaction success" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/transaction/get/abc123", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{
        "id" => "abc123",
        "block_hash" => "000000000000000000",
        "block_height" => 800_000,
        "block_time" => 1_700_000_000,
        "block_index" => 42,
        "addresses" => ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        "inputs" => [],
        "outputs" => [],
        "contexts" => [],
        "data" => []
      }))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, tx} = Client.get_transaction(client, "abc123")
    assert tx.id == "abc123"
    assert tx.block_height == 800_000
    assert tx.block_index == 42
    assert length(tx.addresses) == 1
  end

  test "get transaction not found" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/transaction/get/nonexistent", fn conn ->
      Plug.Conn.resp(conn, 404, "not found")
    end)

    client = Client.new(test_config(bypass.port))
    assert {:error, :not_found} = Client.get_transaction(client, "nonexistent")
  end

  test "get block header" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/block_header/get/800000", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{
        "hash" => "00000000000000000001abc",
        "height" => 800_000,
        "time" => 1_700_000_000,
        "nonce" => 12345,
        "version" => 536_870_912,
        "merkle_root" => "abcdef1234567890",
        "bits" => "18034379",
        "synced" => 1_700_000_100
      }))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, header} = Client.get_block_header(client, "800000")
    assert header.hash == "00000000000000000001abc"
    assert header.height == 800_000
    assert header.merkle_root == "abcdef1234567890"
  end

  test "get block headers list" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/block_header/list/800000", fn conn ->
      assert conn.query_string =~ "limit=5"

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!([
        %{"hash" => "aaa", "height" => 800_000, "time" => 1_700_000_000},
        %{"hash" => "bbb", "height" => 800_001, "time" => 1_700_000_600}
      ]))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, headers} = Client.get_block_headers(client, "800000", 5)
    assert length(headers) == 2
    assert Enum.at(headers, 0).height == 800_000
    assert Enum.at(headers, 1).height == 800_001
  end

  test "get address transactions" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/address/get/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!([
        %{"address" => "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "transaction_count" => 100}
      ]))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, info} = Client.get_address_transactions(client, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert length(info) == 1
    assert Enum.at(info, 0).transaction_count == 100
  end

  test "token header set when configured" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/transaction/get/abc123", fn conn ->
      assert Plug.Conn.get_req_header(conn, "token") == ["test-token"]

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{"id" => "abc123"}))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, _} = Client.get_transaction(client, "abc123")
  end

  test "token header absent when not configured" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/transaction/get/abc123", fn conn ->
      assert Plug.Conn.get_req_header(conn, "token") == []

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{"id" => "abc123"}))
    end)

    config = %Config{server_url: "http://localhost:#{bypass.port}", token: nil, api_version: "v1"}
    client = Client.new(config)
    assert {:ok, _} = Client.get_transaction(client, "abc123")
  end

  test "server error handling" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/transaction/get/abc123", fn conn ->
      Plug.Conn.resp(conn, 500, "internal server error")
    end)

    client = Client.new(test_config(bypass.port))
    assert {:error, err} = Client.get_transaction(client, "abc123")
    assert err.status_code == 500
    assert err.message =~ "internal server error"
  end

  test "config defaults" do
    config = %Config{}
    assert config.server_url == "https://junglebus.gorillapool.io"
    assert config.token == nil
    assert config.api_version == "v1"
  end

  test "get address transaction details" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/v1/address/transactions/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!([
        %{"id" => "tx1", "block_height" => 100},
        %{"id" => "tx2", "block_height" => 101}
      ]))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, txs} = Client.get_address_transaction_details(client, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert length(txs) == 2
    assert Enum.at(txs, 0).id == "tx1"
  end
end
