defmodule BSV.JungleBus.Types do
  @moduledoc "JungleBus data types."

  defmodule Transaction do
    @moduledoc "A transaction returned by the JungleBus API."

    @type t :: %__MODULE__{
            id: String.t(),
            transaction: String.t() | nil,
            block_hash: String.t() | nil,
            block_height: non_neg_integer() | nil,
            block_time: non_neg_integer() | nil,
            block_index: non_neg_integer() | nil,
            addresses: [String.t()],
            inputs: [String.t()],
            outputs: [String.t()],
            input_types: [String.t()],
            output_types: [String.t()],
            contexts: [String.t()],
            sub_contexts: [String.t()],
            data: [String.t()],
            merkle_proof: String.t() | nil
          }

    defstruct id: "",
              transaction: nil,
              block_hash: nil,
              block_height: nil,
              block_time: nil,
              block_index: nil,
              addresses: [],
              inputs: [],
              outputs: [],
              input_types: [],
              output_types: [],
              contexts: [],
              sub_contexts: [],
              data: [],
              merkle_proof: nil

    @doc "Parse a Transaction from a decoded JSON map."
    @spec from_json(map()) :: t()
    def from_json(map) do
      %__MODULE__{
        id: map["id"] || "",
        transaction: map["transaction"],
        block_hash: map["block_hash"],
        block_height: map["block_height"],
        block_time: map["block_time"],
        block_index: map["block_index"],
        addresses: map["addresses"] || [],
        inputs: map["inputs"] || [],
        outputs: map["outputs"] || [],
        input_types: map["input_types"] || [],
        output_types: map["output_types"] || [],
        contexts: map["contexts"] || [],
        sub_contexts: map["sub_contexts"] || [],
        data: map["data"] || [],
        merkle_proof: map["merkle_proof"]
      }
    end
  end

  defmodule BlockHeader do
    @moduledoc "A block header returned by the JungleBus API."

    @type t :: %__MODULE__{
            hash: String.t(),
            coin: non_neg_integer() | nil,
            height: non_neg_integer(),
            time: non_neg_integer(),
            nonce: non_neg_integer() | nil,
            version: non_neg_integer() | nil,
            merkle_root: String.t() | nil,
            bits: String.t() | nil,
            synced: non_neg_integer() | nil
          }

    defstruct hash: "",
              coin: nil,
              height: 0,
              time: 0,
              nonce: nil,
              version: nil,
              merkle_root: nil,
              bits: nil,
              synced: nil

    @doc "Parse a BlockHeader from a decoded JSON map."
    @spec from_json(map()) :: t()
    def from_json(map) do
      %__MODULE__{
        hash: map["hash"] || "",
        coin: map["coin"],
        height: map["height"] || 0,
        time: map["time"] || 0,
        nonce: map["nonce"],
        version: map["version"],
        merkle_root: map["merkle_root"] || map["merkleroot"],
        bits: map["bits"],
        synced: map["synced"]
      }
    end
  end

  defmodule AddressInfo do
    @moduledoc "Address information returned by the JungleBus API."

    @type t :: %__MODULE__{
            address: String.t(),
            transaction_count: non_neg_integer() | nil,
            total_received: non_neg_integer() | nil,
            total_sent: non_neg_integer() | nil
          }

    defstruct address: "",
              transaction_count: nil,
              total_received: nil,
              total_sent: nil

    @doc "Parse an AddressInfo from a decoded JSON map."
    @spec from_json(map()) :: t()
    def from_json(map) do
      %__MODULE__{
        address: map["address"] || "",
        transaction_count: map["transaction_count"],
        total_received: map["total_received"],
        total_sent: map["total_sent"]
      }
    end
  end
end
