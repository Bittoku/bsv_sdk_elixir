defmodule BSV.Transaction.Template do
  @moduledoc "Behaviour for transaction signing templates."

  @callback sign(template :: any(), tx :: BSV.Transaction.t(), input_index :: non_neg_integer()) ::
              {:ok, BSV.Script.t()} | {:error, term()}

  @callback estimate_length(
              template :: any(),
              tx :: BSV.Transaction.t(),
              input_index :: non_neg_integer()
            ) ::
              non_neg_integer()
end
