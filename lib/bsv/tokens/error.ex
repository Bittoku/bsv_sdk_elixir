defmodule BSV.Tokens.Error do
  @moduledoc "Token error types."

  defexception [:message, :type]

  @type error_type ::
          :invalid_scheme
          | :amount_mismatch
          | :invalid_script
          | :invalid_destination
          | :invalid_authority
          | :signing_failed
          | :not_splittable
          | :insufficient_funds
          | :bundle_error

  @type t :: %__MODULE__{
          message: String.t(),
          type: error_type()
        }

  @doc "Create an invalid scheme error."
  @spec invalid_scheme(String.t()) :: t()
  def invalid_scheme(msg), do: %__MODULE__{message: "invalid scheme: #{msg}", type: :invalid_scheme}

  @doc "Create an amount mismatch error."
  @spec amount_mismatch(non_neg_integer(), non_neg_integer()) :: t()
  def amount_mismatch(expected, actual),
    do: %__MODULE__{
      message: "amount mismatch: expected #{expected}, actual #{actual}",
      type: :amount_mismatch
    }

  @doc "Create an invalid script error."
  @spec invalid_script(String.t()) :: t()
  def invalid_script(msg), do: %__MODULE__{message: "invalid script: #{msg}", type: :invalid_script}

  @doc "Create an invalid destination error."
  @spec invalid_destination(String.t()) :: t()
  def invalid_destination(msg),
    do: %__MODULE__{message: "invalid destination: #{msg}", type: :invalid_destination}

  @doc "Create an invalid authority error."
  @spec invalid_authority(String.t()) :: t()
  def invalid_authority(msg),
    do: %__MODULE__{message: "invalid authority: #{msg}", type: :invalid_authority}

  @doc "Create an insufficient funds error."
  @spec insufficient_funds(non_neg_integer(), non_neg_integer()) :: t()
  def insufficient_funds(needed, available),
    do: %__MODULE__{
      message: "insufficient funds: needed #{needed}, available #{available}",
      type: :insufficient_funds
    }
end
