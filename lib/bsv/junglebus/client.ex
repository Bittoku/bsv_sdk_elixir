defmodule BSV.JungleBus.Client do
  @moduledoc "HTTP client for the JungleBus API."

  alias BSV.JungleBus.{Config, Error}
  alias BSV.JungleBus.Types.{Transaction, BlockHeader, AddressInfo}

  @type t :: %__MODULE__{config: Config.t(), req: Req.Request.t()}

  defstruct [:config, :req]

  @doc "Create a new JungleBus client with the given configuration."
  @spec new(Config.t()) :: t()
  def new(%Config{} = config) do
    base_url = "#{config.server_url}/#{config.api_version}"
    req = Req.new(base_url: base_url, retry: false)
    %__MODULE__{config: config, req: req}
  end

  @doc "Get a transaction by its ID."
  @spec get_transaction(t(), String.t()) :: {:ok, Transaction.t()} | {:error, term()}
  def get_transaction(%__MODULE__{} = client, txid) do
    do_request(client, "/transaction/get/#{URI.encode_www_form(txid)}", &Transaction.from_json/1)
  end

  @doc "Get address transaction metadata."
  @spec get_address_transactions(t(), String.t()) :: {:ok, [AddressInfo.t()]} | {:error, term()}
  def get_address_transactions(%__MODULE__{} = client, address) do
    do_request(client, "/address/get/#{URI.encode_www_form(address)}", fn data ->
      parse_list(data, &AddressInfo.from_json/1)
    end)
  end

  @doc "Get full transaction details for an address."
  @spec get_address_transaction_details(t(), String.t()) ::
          {:ok, [Transaction.t()]} | {:error, term()}
  def get_address_transaction_details(%__MODULE__{} = client, address) do
    do_request(client, "/address/transactions/#{URI.encode_www_form(address)}", fn data ->
      parse_list(data, &Transaction.from_json/1)
    end)
  end

  @doc "Get a block header by hash or height."
  @spec get_block_header(t(), String.t()) :: {:ok, BlockHeader.t()} | {:error, term()}
  def get_block_header(%__MODULE__{} = client, block) do
    do_request(client, "/block_header/get/#{URI.encode_www_form(block)}", &BlockHeader.from_json/1)
  end

  @doc "List block headers starting from a given block."
  @spec get_block_headers(t(), String.t(), non_neg_integer()) ::
          {:ok, [BlockHeader.t()]} | {:error, term()}
  def get_block_headers(%__MODULE__{} = client, from_block, limit) do
    do_request(
      client,
      "/block_header/list/#{URI.encode_www_form(from_block)}?limit=#{limit}",
      fn data -> parse_list(data, &BlockHeader.from_json/1) end
    )
  end

  defp do_request(%__MODULE__{} = client, path, parser) do
    headers = build_headers(client.config)

    case Req.get(client.req, url: path, headers: headers) do
      {:ok, %Req.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Req.Response{status: status, body: body}} when status >= 200 and status < 300 ->
        parse_body(body, parser)

      {:ok, %Req.Response{status: status, body: body}} ->
        msg = if is_binary(body), do: body, else: Jason.encode!(body)
        {:error, %Error{type: :server_error, status_code: status, message: msg}}

      {:error, reason} ->
        {:error, %Error{type: :http, message: "HTTP error: #{inspect(reason)}"}}
    end
  end

  defp parse_body(body, parser) when is_map(body), do: {:ok, parser.(body)}
  defp parse_body(body, parser) when is_list(body), do: {:ok, parser.(body)}

  defp parse_body(body, parser) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> {:ok, parser.(decoded)}
      {:error, _} -> {:error, %Error{type: :serialization, message: "invalid JSON response"}}
    end
  end

  defp parse_list(list, mapper) when is_list(list), do: Enum.map(list, mapper)

  defp build_headers(%Config{} = config) do
    if config.token, do: [{"token", config.token}], else: []
  end
end
