defmodule BSV.ARC.ClientTest do
  use ExUnit.Case, async: true

  alias BSV.ARC.{Client, Config, Types}

  defp test_config(port) do
    %Config{
      base_url: "http://localhost:#{port}",
      api_key: "test-key",
      callback_url: "https://example.com/callback",
      callback_token: "cb-token",
      wait_for_status: :seen_on_network,
      skip_fee_validation: true,
      skip_script_validation: true,
      skip_tx_validation: true,
      cumulative_fee_validation: true,
      full_status_updates: true,
      max_timeout: 30
    }
  end

  defp dummy_tx, do: BSV.Transaction.new()

  test "successful broadcast" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "POST", "/tx", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{
        "txid" => "abc123",
        "txStatus" => "SEEN_ON_NETWORK",
        "status" => 8,
        "title" => "OK"
      }))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, resp} = Client.broadcast(client, dummy_tx())
    assert resp.txid == "abc123"
    assert resp.tx_status == "SEEN_ON_NETWORK"
    assert resp.status == 8
  end

  test "rejected transaction" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "POST", "/tx", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{
        "txid" => "abc123",
        "txStatus" => "REJECTED",
        "status" => 0,
        "detail" => "dust output"
      }))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:error, err} = Client.broadcast(client, dummy_tx())
    assert err.type == :rejected
    assert err.message =~ "dust output"
  end

  @test_txid "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

  test "status query" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/tx/#{@test_txid}", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{
        "txid" => @test_txid,
        "txStatus" => "MINED",
        "status" => 9,
        "blockHeight" => 800_000,
        "blockHash" => "00000000000000000001"
      }))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, resp} = Client.status(client, @test_txid)
    assert resp.txid == @test_txid
    assert resp.block_height == 800_000
  end

  test "headers are set" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "POST", "/tx", fn conn ->
      assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer test-key"]
      assert Plug.Conn.get_req_header(conn, "x-callbackurl") == ["https://example.com/callback"]
      assert Plug.Conn.get_req_header(conn, "x-callbacktoken") == ["cb-token"]
      assert Plug.Conn.get_req_header(conn, "x-waitforstatus") == ["8"]
      assert Plug.Conn.get_req_header(conn, "x-skipfeevalidation") == ["true"]
      assert Plug.Conn.get_req_header(conn, "x-skipscriptvalidation") == ["true"]
      assert Plug.Conn.get_req_header(conn, "x-skiptxvalidation") == ["true"]
      assert Plug.Conn.get_req_header(conn, "x-cumulativefeevalidation") == ["true"]
      assert Plug.Conn.get_req_header(conn, "x-fullstatusupdates") == ["true"]
      assert Plug.Conn.get_req_header(conn, "x-maxtimeout") == ["30"]
      assert Plug.Conn.get_req_header(conn, "content-type") == ["application/octet-stream"]

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{"txid" => "abc123", "txStatus" => "QUEUED", "status" => 1}))
    end)

    client = Client.new(test_config(bypass.port))
    assert {:ok, resp} = Client.broadcast(client, dummy_tx())
    assert resp.txid == "abc123"
  end

  test "config defaults" do
    config = %Config{}
    assert config.base_url == "https://arc.taal.com/v1"
    assert config.api_key == nil
    assert config.skip_fee_validation == false
    assert config.skip_script_validation == false
    assert config.skip_tx_validation == false
    assert config.cumulative_fee_validation == false
    assert config.full_status_updates == false
    assert config.max_timeout == nil
  end

  test "no auth header when no api key" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "POST", "/tx", fn conn ->
      assert Plug.Conn.get_req_header(conn, "authorization") == []

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{"txid" => "abc123", "txStatus" => "QUEUED", "status" => 1}))
    end)

    config = %Config{base_url: "http://localhost:#{bypass.port}"}
    client = Client.new(config)
    assert {:ok, resp} = Client.broadcast(client, dummy_tx())
    assert resp.txid == "abc123"
  end

  test "malformed JSON response" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "POST", "/tx", fn conn ->
      Plug.Conn.resp(conn, 200, "{not valid json")
    end)

    config = %Config{base_url: "http://localhost:#{bypass.port}"}
    client = Client.new(config)
    assert {:error, _} = Client.broadcast(client, dummy_tx())
  end

  test "empty response body" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "POST", "/tx", fn conn ->
      Plug.Conn.resp(conn, 200, "")
    end)

    config = %Config{base_url: "http://localhost:#{bypass.port}"}
    client = Client.new(config)
    assert {:error, _} = Client.broadcast(client, dummy_tx())
  end

  test "already known tx" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "POST", "/tx", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{
        "txid" => "abc123",
        "txStatus" => "SEEN_ON_NETWORK",
        "status" => 8,
        "title" => "Already known"
      }))
    end)

    config = %Config{base_url: "http://localhost:#{bypass.port}"}
    client = Client.new(config)
    assert {:ok, resp} = Client.broadcast(client, dummy_tx())
    assert resp.title == "Already known"
  end

  test "mined response with merkle path" do
    bypass = Bypass.open()

    Bypass.expect(bypass, "GET", "/tx/#{@test_txid}", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{
        "txid" => @test_txid,
        "txStatus" => "MINED",
        "status" => 9,
        "blockHeight" => 850_000,
        "blockHash" => "000000000000000000026f5a9cf8e64507d75e70a9c37acac5b59a5e8c4dfe3c",
        "merklePath" => "fed123abc"
      }))
    end)

    config = %Config{base_url: "http://localhost:#{bypass.port}"}
    client = Client.new(config)
    assert {:ok, resp} = Client.status(client, @test_txid)
    assert resp.block_height == 850_000
    assert resp.merkle_path == "fed123abc"
  end

  test "status query rejects invalid txid format" do
    config = %Config{base_url: "http://localhost:9999"}
    client = Client.new(config)
    assert {:error, err} = Client.status(client, "nonexistent")
    assert err.type == :validation
    assert err.message =~ "invalid txid format"
  end

  test "status query not found returns response" do
    bypass = Bypass.open()
    not_found_txid = "0000000000000000000000000000000000000000000000000000000000000000"

    Bypass.expect(bypass, "GET", "/tx/#{not_found_txid}", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{"txid" => "", "status" => 0, "title" => "Not found"}))
    end)

    config = %Config{base_url: "http://localhost:#{bypass.port}"}
    client = Client.new(config)
    # ARC returns 200 with JSON for not-found, caller checks status
    assert {:ok, resp} = Client.status(client, not_found_txid)
    assert resp.title == "Not found"
  end

  test "arc status codes" do
    assert Types.status_code(:rejected) == 0
    assert Types.status_code(:seen_on_network) == 8
    assert Types.status_code(:mined) == 9
    assert Types.status_code(:confirmed) == 10
  end

  test "arc status strings" do
    assert Types.status_string(:mined) == "MINED"
    assert Types.status_string(:seen_on_network) == "SEEN_ON_NETWORK"
    assert Types.status_string(:double_spend_attempted) == "DOUBLE_SPEND_ATTEMPTED"
  end

  test "parse status round-trip" do
    for status <- Types.all_statuses() do
      str = Types.status_string(status)
      assert {:ok, ^status} = Types.parse_status(str)
    end
  end

  test "parse invalid status" do
    assert :error = Types.parse_status("INVALID")
  end
end
