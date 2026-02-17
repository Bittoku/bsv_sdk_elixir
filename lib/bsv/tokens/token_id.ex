defmodule BSV.Tokens.TokenId do
  @moduledoc "Token identifier derived from a BSV address."

  @type t :: %__MODULE__{
          address_string: String.t(),
          pkh: <<_::160>>
        }

  defstruct [:address_string, :pkh]

  @spec from_address(String.t(), <<_::160>>) :: t()
  def from_address(address_string, <<pkh::binary-size(20)>>) do
    %__MODULE__{address_string: address_string, pkh: pkh}
  end

  @spec from_string(String.t()) :: t()
  def from_string(address_string) do
    %__MODULE__{address_string: address_string, pkh: <<0::160>>}
  end

  @spec from_pkh(<<_::160>>) :: t()
  def from_pkh(<<pkh::binary-size(20)>>) do
    hex = Base.encode16(pkh, case: :lower)
    %__MODULE__{address_string: hex, pkh: pkh}
  end

  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{address_string: addr}), do: addr

  defimpl String.Chars do
    def to_string(%BSV.Tokens.TokenId{address_string: addr}), do: addr
  end

  defimpl Jason.Encoder do
    def encode(%BSV.Tokens.TokenId{address_string: addr, pkh: pkh}, opts) do
      Jason.Encode.map(
        %{
          "address_string" => addr,
          "pkh" => Base.encode16(pkh, case: :lower)
        },
        opts
      )
    end
  end
end
