defmodule BSV.ContractTest do
  use ExUnit.Case, async: true
  alias BSV.{Contract, Script}
  alias BSV.Contract.{P2PKH, P2PK, P2MS, OpReturn, Raw}

  @pubkey_hash :crypto.hash(:ripemd160, :crypto.hash(:sha256, "test"))
               |> binary_part(0, 20)
  @pubkey :crypto.strong_rand_bytes(33)
  @sig :crypto.strong_rand_bytes(72)

  describe "Contract pipeline basics" do
    test "push data onto script" do
      contract = %Contract{mfa: {__MODULE__, :identity, [%{}]}}
      result = BSV.Contract.Helpers.push(contract, <<1, 2, 3>>)
      assert result.script.chunks == [{:data, <<1, 2, 3>>}]
    end

    test "push opcode onto script" do
      contract = %Contract{mfa: {__MODULE__, :identity, [%{}]}}
      result = BSV.Contract.Helpers.op_dup(contract)
      assert result.script.chunks == [{:op, 0x76}]
    end

    test "push integer 0 becomes OP_0" do
      contract = %Contract{mfa: {__MODULE__, :identity, [%{}]}}
      result = BSV.Contract.Helpers.push(contract, 0)
      assert result.script.chunks == [{:op, 0x00}]
    end

    test "push integer 1-16 becomes OP_1..OP_16" do
      contract = %Contract{mfa: {__MODULE__, :identity, [%{}]}}
      result = BSV.Contract.Helpers.push(contract, 5)
      assert result.script.chunks == [{:op, 0x55}]
    end

    test "push list of data" do
      contract = %Contract{mfa: {__MODULE__, :identity, [%{}]}}
      result = BSV.Contract.Helpers.push(contract, [<<1>>, <<2>>, <<3>>])
      assert length(result.script.chunks) == 3
    end
  end

  describe "P2PKH" do
    test "locking script structure" do
      contract = P2PKH.lock(1000, %{pubkey_hash: @pubkey_hash})
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:op, 0x76},  # OP_DUP
               {:op, 0xA9},  # OP_HASH160
               {:data, @pubkey_hash},
               {:op, 0x88},  # OP_EQUALVERIFY
               {:op, 0xAC}   # OP_CHECKSIG
             ]
    end

    test "locking script compiles to binary" do
      contract = P2PKH.lock(1000, %{pubkey_hash: @pubkey_hash})
      bin = Contract.to_binary(contract)
      assert is_binary(bin)
      assert byte_size(bin) == 25  # 3 ops + 1 pushdata + 20 bytes + 2 ops
    end

    test "unlocking script structure" do
      contract = P2PKH.unlock(%{}, %{signature: @sig, pubkey: @pubkey})
      script = Contract.to_script(contract)
      assert length(script.chunks) == 2
    end

    test "subject carries satoshis" do
      contract = P2PKH.lock(5000, %{pubkey_hash: @pubkey_hash})
      assert contract.subject == 5000
    end
  end

  describe "P2PK" do
    test "locking script structure" do
      contract = P2PK.lock(1000, %{pubkey: @pubkey})
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:data, @pubkey},
               {:op, 0xAC}  # OP_CHECKSIG
             ]
    end
  end

  describe "P2MS" do
    test "locking script structure" do
      pk1 = :crypto.strong_rand_bytes(33)
      pk2 = :crypto.strong_rand_bytes(33)
      pk3 = :crypto.strong_rand_bytes(33)

      contract = P2MS.lock(1000, %{pubkeys: [pk1, pk2, pk3], threshold: 2})
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:op, 0x52},  # OP_2
               {:data, pk1},
               {:data, pk2},
               {:data, pk3},
               {:op, 0x53},  # OP_3
               {:op, 0xAE}   # OP_CHECKMULTISIG
             ]
    end

    test "unlocking script with 2 signatures" do
      sig1 = :crypto.strong_rand_bytes(72)
      sig2 = :crypto.strong_rand_bytes(72)

      contract = P2MS.unlock(%{}, %{signatures: [sig1, sig2]})
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:op, 0x00},  # OP_0 (multisig bug)
               {:data, sig1},
               {:data, sig2}
             ]
    end
  end

  describe "OpReturn" do
    test "single data" do
      contract = OpReturn.lock(0, %{data: "hello world"})
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:op, 0x00},  # OP_FALSE
               {:op, 0x6A},  # OP_RETURN
               {:data, "hello world"}
             ]
    end

    test "multiple data pushes" do
      contract = OpReturn.lock(0, %{data: ["hello", "world"]})
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:op, 0x00},
               {:op, 0x6A},
               {:data, "hello"},
               {:data, "world"}
             ]
    end
  end

  describe "Raw" do
    test "wraps existing script" do
      existing = %Script{chunks: [{:op, 0x76}, {:op, 0xAC}]}
      contract = Raw.lock(1000, %{script: existing})
      assert Contract.to_script(contract) == existing
    end
  end

  describe "to_binary/1 roundtrip" do
    test "P2PKH locking script matches manual construction" do
      contract = P2PKH.lock(1000, %{pubkey_hash: @pubkey_hash})
      bin = Contract.to_binary(contract)

      # Manual P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      manual = Script.p2pkh_lock(@pubkey_hash)
      assert bin == Script.to_binary(manual)
    end
  end

  describe "script_size/1" do
    test "returns correct size" do
      contract = P2PKH.lock(1000, %{pubkey_hash: @pubkey_hash})
      assert Contract.script_size(contract) == 25
    end
  end

  describe "flow control helpers" do
    test "op_if with callback" do
      contract = %Contract{mfa: {__MODULE__, :if_test, [%{}]}}
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:op, 0x63},  # OP_IF
               {:op, 0x76},  # OP_DUP
               {:op, 0x68}   # OP_ENDIF
             ]
    end

    test "op_if with if/else callbacks" do
      contract = %Contract{mfa: {__MODULE__, :if_else_test, [%{}]}}
      script = Contract.to_script(contract)

      assert script.chunks == [
               {:op, 0x63},  # OP_IF
               {:op, 0x76},  # OP_DUP
               {:op, 0x67},  # OP_ELSE
               {:op, 0x75},  # OP_DROP
               {:op, 0x68}   # OP_ENDIF
             ]
    end
  end

  # Test helper callbacks
  def identity(ctx, _params), do: ctx

  import BSV.Contract.Helpers

  def if_test(ctx, _params) do
    op_if(ctx, &op_dup/1)
  end

  def if_else_test(ctx, _params) do
    op_if(ctx, &op_dup/1, &op_drop/1)
  end
end
