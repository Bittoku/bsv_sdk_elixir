defmodule BSV.Script.AddressTest do
  use ExUnit.Case, async: true

  alias BSV.Script
  alias BSV.Script.Address

  describe "from_script/1 and to_script/1 roundtrip" do
    test "mainnet P2PKH roundtrip" do
      {:ok, script} = Script.from_hex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
      {:ok, addr} = Address.from_script(script)
      {:ok, script2} = Address.to_script(addr)
      assert Script.to_hex(script2) == Script.to_hex(script)
    end

    test "from known address" do
      # Known address -> script -> address roundtrip
      pkh = Base.decode16!("e2a623699e81b291c0327f408fea765d534baa2a", case: :lower)
      script = Script.p2pkh_lock(pkh)
      {:ok, addr} = Address.from_script(script)
      assert is_binary(addr)
      {:ok, script2} = Address.to_script(addr)
      assert Script.to_hex(script2) == Script.to_hex(script)
    end

    test "testnet roundtrip" do
      pkh = Base.decode16!("e2a623699e81b291c0327f408fea765d534baa2a", case: :lower)
      script = Script.p2pkh_lock(pkh)
      {:ok, addr} = Address.from_script(script, :testnet)
      {:ok, script2} = Address.to_script(addr)
      assert Script.to_hex(script2) == Script.to_hex(script)
    end
  end

  describe "from_script/1 errors" do
    test "returns :error for non-P2PKH" do
      {:ok, script} = Script.from_hex("a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87")
      assert :error = Address.from_script(script)
    end
  end

  describe "to_script/1 errors" do
    test "returns error for invalid address" do
      assert {:error, _} = Address.to_script("invalidaddress")
    end

    test "returns error for unsupported address version" do
      # Encode with version 0x05 (P2SH) which is not supported
      payload = :crypto.strong_rand_bytes(20)
      addr = BSV.Base58.check_encode(payload, 0x05)
      assert {:error, :unsupported_address} = Address.to_script(addr)
    end
  end
end
