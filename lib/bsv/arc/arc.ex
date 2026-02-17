defmodule BSV.ARC.Client do
  @moduledoc "HTTP client for the ARC API."

  alias BSV.ARC.{Config, Error, Types}
  alias BSV.ARC.Types.Response, as: ArcResponse

  @type t :: %__MODULE__{config: Config.t(), req: Req.Request.t()}

  defstruct [:config, :req]

  @doc "Create a new ARC client with the given configuration."
  @spec new(Config.t()) :: t()
  def new(%Config{} = config) do
    req = Req.new(base_url: config.base_url, retry: false)
    %__MODULE__{config: config, req: req}
  end

  @doc "Broadcast a transaction to the ARC API."
  @spec broadcast(t(), BSV.Transaction.t()) :: {:ok, ArcResponse.t()} | {:error, term()}
  def broadcast(%__MODULE__{} = client, %BSV.Transaction{} = tx) do
    raw_tx = BSV.Transaction.to_binary(tx)
    headers = build_headers(client.config)

    case Req.post(client.req,
           url: "/tx",
           headers: [{"content-type", "application/octet-stream"} | headers],
           body: raw_tx
         ) do
      {:ok, %Req.Response{status: _status, body: body}} when is_binary(body) ->
        parse_json_response(body)

      {:ok, %Req.Response{body: body}} when is_map(body) ->
        check_response(ArcResponse.from_json(body))

      {:ok, %Req.Response{body: body}} when is_binary(body) ->
        parse_json_response(body)

      {:error, reason} ->
        {:error, %Error{type: :http, message: "HTTP error: #{inspect(reason)}"}}
    end
  end

  @doc "Query the status of a transaction by txid."
  @spec status(t(), String.t()) :: {:ok, ArcResponse.t()} | {:error, term()}
  def status(%__MODULE__{} = client, txid) when is_binary(txid) do
    headers = build_headers(client.config)

    case Req.get(client.req, url: "/tx/#{txid}", headers: headers) do
      {:ok, %Req.Response{body: body}} when is_map(body) ->
        {:ok, ArcResponse.from_json(body)}

      {:ok, %Req.Response{body: body}} when is_binary(body) ->
        case Jason.decode(body) do
          {:ok, map} -> {:ok, ArcResponse.from_json(map)}
          {:error, _} -> {:error, %Error{type: :serialization, message: "invalid JSON response"}}
        end

      {:error, reason} ->
        {:error, %Error{type: :http, message: "HTTP error: #{inspect(reason)}"}}
    end
  end

  defp parse_json_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, map} -> check_response(ArcResponse.from_json(map))
      {:error, _} -> {:error, %Error{type: :serialization, message: "invalid JSON response"}}
    end
  end

  defp check_response(%ArcResponse{status: 0, detail: detail}) do
    {:error,
     %Error{
       type: :rejected,
       code: 0,
       message: "transaction rejected (0): #{detail || "rejected"}"
     }}
  end

  defp check_response(%ArcResponse{} = resp), do: {:ok, resp}

  defp build_headers(%Config{} = config) do
    []
    |> maybe_add("authorization", config.api_key, &"Bearer #{&1}")
    |> maybe_add("x-callbackurl", config.callback_url)
    |> maybe_add("x-callbacktoken", config.callback_token)
    |> maybe_add("x-waitforstatus", config.wait_for_status, &to_string(Types.status_code(&1)))
    |> maybe_add_bool("x-skipfeevalidation", config.skip_fee_validation)
    |> maybe_add_bool("x-skipscriptvalidation", config.skip_script_validation)
    |> maybe_add_bool("x-skiptxvalidation", config.skip_tx_validation)
    |> maybe_add_bool("x-cumulativefeevalidation", config.cumulative_fee_validation)
    |> maybe_add_bool("x-fullstatusupdates", config.full_status_updates)
    |> maybe_add("x-maxtimeout", config.max_timeout, &to_string/1)
  end

  defp maybe_add(headers, _name, nil, _transform), do: headers
  defp maybe_add(headers, name, value, transform), do: [{name, transform.(value)} | headers]

  defp maybe_add(headers, _name, nil), do: headers
  defp maybe_add(headers, name, value), do: [{name, value} | headers]

  defp maybe_add_bool(headers, _name, false), do: headers
  defp maybe_add_bool(headers, name, true), do: [{name, "true"} | headers]
end
