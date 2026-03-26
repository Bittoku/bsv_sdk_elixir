defmodule BSV.Transaction.P2MPKHTest do
  use ExUnit.Case, async: true

  alias BSV.Transaction.P2MPKH
  alias BSV.{Crypto, PrivateKey, PublicKey}

  defp gen_keys(n) do
    privs = for _ <- 1..n, do: PrivateKey.generate()
    pubs = Enum.map(privs, fn k -> PrivateKey.to_public_key(k) |> PublicKey.compress() |> Map.get(:point) end)
    {privs, pubs}
  end

  describe "new_multisig/2" do
    test "creates 2-of-3 multisig" do
      {_privs, pubs} = gen_keys(3)
      assert {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      assert ms.threshold == 2
      assert length(ms.public_keys) == 3
    end

    test "creates 1-of-1 multisig" do
      {_privs, pubs} = gen_keys(1)
      assert {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      assert ms.threshold == 1
    end

    test "rejects threshold 0" do
      {_privs, pubs} = gen_keys(3)
      assert {:error, :threshold_too_low} = P2MPKH.new_multisig(0, pubs)
    end

    test "rejects threshold exceeding keys" do
      {_privs, pubs} = gen_keys(2)
      assert {:error, {:threshold_exceeds_keys, 3, 2}} = P2MPKH.new_multisig(3, pubs)
    end

    test "rejects empty keys" do
      assert {:error, :no_public_keys} = P2MPKH.new_multisig(1, [])
    end

    test "rejects too many keys" do
      {_privs, pubs} = gen_keys(17)
      assert {:error, {:too_many_keys, 17}} = P2MPKH.new_multisig(1, pubs)
    end

    test "rejects non-33-byte keys" do
      assert {:error, :invalid_public_key_size} = P2MPKH.new_multisig(1, [<<1, 2, 3>>])
    end
  end

  describe "to_script_bytes/1 and from_script_bytes/1" do
    test "roundtrip 2-of-3" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      bytes = P2MPKH.to_script_bytes(ms)
      assert {:ok, ms2} = P2MPKH.from_script_bytes(bytes)
      assert ms2.threshold == 2
      assert length(ms2.public_keys) == 3
      assert ms2.public_keys == pubs
    end

    test "roundtrip 1-of-1" do
      {_privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      bytes = P2MPKH.to_script_bytes(ms)
      assert byte_size(bytes) == 37
      assert {:ok, ms2} = P2MPKH.from_script_bytes(bytes)
      assert ms2.threshold == 1
      assert ms2.public_keys == pubs
    end

    test "rejects garbage" do
      assert {:error, _} = P2MPKH.from_script_bytes(<<0x00, 0x01, 0x02>>)
    end
  end

  describe "mpkh/1" do
    test "returns 20 bytes" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      mpkh = P2MPKH.mpkh(ms)
      assert byte_size(mpkh) == 20
    end

    test "is deterministic" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      assert P2MPKH.mpkh(ms) == P2MPKH.mpkh(ms)
    end

    test "differs for different key sets" do
      {_privs1, pubs1} = gen_keys(3)
      {_privs2, pubs2} = gen_keys(3)
      {:ok, ms1} = P2MPKH.new_multisig(2, pubs1)
      {:ok, ms2} = P2MPKH.new_multisig(2, pubs2)
      assert P2MPKH.mpkh(ms1) != P2MPKH.mpkh(ms2)
    end

    test "differs for different thresholds" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms1} = P2MPKH.new_multisig(1, pubs)
      {:ok, ms2} = P2MPKH.new_multisig(2, pubs)
      assert P2MPKH.mpkh(ms1) != P2MPKH.mpkh(ms2)
    end

    test "equals HASH160 of script bytes" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      assert P2MPKH.mpkh(ms) == Crypto.hash160(P2MPKH.to_script_bytes(ms))
    end
  end

  describe "lock/1" do
    test "produces a script" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      assert {:ok, script} = P2MPKH.lock(ms)
      assert %BSV.Script{} = script
    end
  end

  describe "unlock/2" do
    test "creates unlocker with correct key count" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      assert {:ok, _unlocker} = P2MPKH.unlock(Enum.take(privs, 2), ms)
    end

    test "rejects wrong key count" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      assert {:error, {:wrong_key_count, 2, 3}} = P2MPKH.unlock(privs, ms)
    end
  end

  describe "estimate_length/3" do
    test "2-of-3 estimate exceeds P2PKH" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 2), ms)
      est = P2MPKH.estimate_length(unlocker, nil, nil)
      assert est > 106
      assert est == 1 + 2 * 73
    end
  end
end
