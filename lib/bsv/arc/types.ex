defmodule BSV.ARC.Types do
  @moduledoc "ARC data types: status codes and API response structures."

  @type arc_status ::
          :rejected
          | :queued
          | :received
          | :stored
          | :announced_to_network
          | :requested_by_network
          | :sent_to_network
          | :accepted_by_network
          | :seen_on_network
          | :mined
          | :confirmed
          | :double_spend_attempted
          | :seen_in_orphan_mempool

  @status_codes %{
    rejected: 0,
    queued: 1,
    received: 2,
    stored: 3,
    announced_to_network: 4,
    requested_by_network: 5,
    sent_to_network: 6,
    accepted_by_network: 7,
    seen_on_network: 8,
    mined: 9,
    confirmed: 10,
    double_spend_attempted: 11,
    seen_in_orphan_mempool: 12
  }

  @status_strings %{
    rejected: "REJECTED",
    queued: "QUEUED",
    received: "RECEIVED",
    stored: "STORED",
    announced_to_network: "ANNOUNCED_TO_NETWORK",
    requested_by_network: "REQUESTED_BY_NETWORK",
    sent_to_network: "SENT_TO_NETWORK",
    accepted_by_network: "ACCEPTED_BY_NETWORK",
    seen_on_network: "SEEN_ON_NETWORK",
    mined: "MINED",
    confirmed: "CONFIRMED",
    double_spend_attempted: "DOUBLE_SPEND_ATTEMPTED",
    seen_in_orphan_mempool: "SEEN_IN_ORPHAN_MEMPOOL"
  }

  @doc "Returns the integer code for an ARC status atom."
  @spec status_code(arc_status()) :: integer()
  def status_code(status), do: Map.fetch!(@status_codes, status)

  @doc "Returns the string representation for an ARC status atom."
  @spec status_string(arc_status()) :: String.t()
  def status_string(status), do: Map.fetch!(@status_strings, status)

  @doc "Parses a status string like `\"MINED\"` to an atom."
  @spec parse_status(String.t()) :: {:ok, arc_status()} | :error
  def parse_status(str) do
    case Enum.find(@status_strings, fn {_k, v} -> v == str end) do
      {k, _v} -> {:ok, k}
      nil -> :error
    end
  end

  @doc "All valid status atoms."
  @spec all_statuses() :: [arc_status()]
  def all_statuses, do: Map.keys(@status_codes)

  defmodule Response do
    @moduledoc "Response from the ARC API."

    @type t :: %__MODULE__{
            txid: String.t(),
            tx_status: String.t() | nil,
            status: integer() | nil,
            title: String.t() | nil,
            block_hash: String.t() | nil,
            block_height: non_neg_integer() | nil,
            extra_info: String.t() | nil,
            timestamp: String.t() | nil,
            instance: String.t() | nil,
            detail: String.t() | nil,
            merkle_path: String.t() | nil
          }

    defstruct [
      :txid,
      :tx_status,
      :status,
      :title,
      :block_hash,
      :block_height,
      :extra_info,
      :timestamp,
      :instance,
      :detail,
      :merkle_path
    ]

    @doc "Parse a JSON map (string keys, camelCase) into an ArcResponse."
    @spec from_json(map()) :: t()
    def from_json(map) when is_map(map) do
      %__MODULE__{
        txid: map["txid"] || "",
        tx_status: map["txStatus"],
        status: map["status"],
        title: map["title"],
        block_hash: map["blockHash"],
        block_height: map["blockHeight"],
        extra_info: map["extraInfo"],
        timestamp: map["timestamp"],
        instance: map["instance"],
        detail: map["detail"],
        merkle_path: map["merklePath"]
      }
    end
  end
end
