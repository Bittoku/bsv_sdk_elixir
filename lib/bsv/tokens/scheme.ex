defmodule BSV.Tokens.Authority do
  @moduledoc "Multi-signature authority configuration for token governance."

  @type t :: %__MODULE__{
          m: non_neg_integer(),
          public_keys: [String.t()]
        }

  @derive Jason.Encoder
  defstruct [:m, public_keys: []]

  @doc "Validate the authority configuration (m-of-n keys)."
  @spec validate(t()) :: :ok | {:error, BSV.Tokens.Error.t()}
  def validate(%__MODULE__{m: m, public_keys: keys}) do
    cond do
      keys == [] ->
        {:error, BSV.Tokens.Error.invalid_authority("at least one public key is required")}

      m == 0 ->
        {:error, BSV.Tokens.Error.invalid_authority("m must be at least 1")}

      m > length(keys) ->
        {:error,
         BSV.Tokens.Error.invalid_authority(
           "m (#{m}) exceeds number of public keys (#{length(keys)})"
         )}

      true ->
        :ok
    end
  end
end

defmodule BSV.Tokens.Scheme do
  @moduledoc "Token scheme defining the properties of a token."

  alias BSV.Tokens.{Authority, TokenId}

  @type t :: %__MODULE__{
          name: String.t(),
          token_id: TokenId.t(),
          symbol: String.t(),
          satoshis_per_token: non_neg_integer(),
          freeze: boolean(),
          confiscation: boolean(),
          is_divisible: boolean(),
          authority: Authority.t()
        }

  defstruct [
    :name,
    :token_id,
    :symbol,
    :satoshis_per_token,
    freeze: false,
    confiscation: false,
    is_divisible: true,
    authority: %Authority{}
  ]

  @doc "Serialize the token scheme to a JSON string."
  @spec to_json(t()) :: {:ok, binary()} | {:error, term()}
  def to_json(%__MODULE__{} = scheme) do
    Jason.encode(%{
      name: scheme.name,
      token_id: scheme.token_id,
      symbol: scheme.symbol,
      satoshis_per_token: scheme.satoshis_per_token,
      freeze: scheme.freeze,
      confiscation: scheme.confiscation,
      is_divisible: scheme.is_divisible,
      authority: scheme.authority
    })
  end

  @doc "Deserialize a token scheme from a JSON string."
  @spec from_json(binary()) :: {:ok, t()} | {:error, term()}
  def from_json(json) when is_binary(json) do
    with {:ok, map} <- Jason.decode(json),
         :ok <- validate_required_fields(map) do
      token_id =
        case map["token_id"] do
          %{"address_string" => addr, "pkh" => pkh_hex} ->
            {:ok, pkh} = Base.decode16(pkh_hex, case: :mixed)
            TokenId.from_address(addr, pkh)

          _ ->
            TokenId.from_string("")
        end

      authority = case map["authority"] do
        %{"m" => m, "public_keys" => keys} when is_integer(m) and is_list(keys) ->
          %Authority{m: m, public_keys: keys}
        %{"m" => m} when is_integer(m) ->
          %Authority{m: m, public_keys: []}
        _ ->
          %Authority{m: 1, public_keys: []}
      end

      {:ok,
       %__MODULE__{
         name: map["name"],
         token_id: token_id,
         symbol: map["symbol"],
         satoshis_per_token: map["satoshis_per_token"],
         freeze: map["freeze"] || false,
         confiscation: map["confiscation"] || false,
         is_divisible: map["is_divisible"] || true,
         authority: authority
       }}
    end
  end

  defp validate_required_fields(map) do
    cond do
      not is_binary(map["name"]) or map["name"] == "" ->
        {:error, "scheme requires a non-empty 'name' string"}

      not is_binary(map["symbol"]) or map["symbol"] == "" ->
        {:error, "scheme requires a non-empty 'symbol' string"}

      not is_integer(map["satoshis_per_token"]) or map["satoshis_per_token"] <= 0 ->
        {:error, "scheme requires a positive integer 'satoshis_per_token'"}

      true ->
        :ok
    end
  end
end
