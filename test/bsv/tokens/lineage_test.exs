defmodule BSV.Tokens.LineageTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Lineage

  test "validator creation" do
    contract_txid = :binary.copy(<<0x01>>, 32)
    rpkh = :binary.copy(<<0xAA>>, 20)
    validator = Lineage.new(contract_txid, rpkh)

    assert Lineage.is_validated?(validator, contract_txid)
    assert Lineage.validated_count(validator) == 1
  end

  test "contract txid validates immediately" do
    contract_txid = :binary.copy(<<0x01>>, 32)
    rpkh = :binary.copy(<<0xAA>>, 20)
    validator = Lineage.new(contract_txid, rpkh)

    fetcher = fn _txid -> {:error, "should not be called"} end
    assert {:ok, _validator} = Lineage.validate(validator, contract_txid, 0, fetcher)
  end

  test "validate unknown tx fails" do
    contract_txid = :binary.copy(<<0x01>>, 32)
    rpkh = :binary.copy(<<0xAA>>, 20)
    validator = Lineage.new(contract_txid, rpkh)

    unknown_txid = :binary.copy(<<0x99>>, 32)
    fetcher = fn _txid -> {:error, "tx not found"} end

    assert {:error, "tx not found"} = Lineage.validate(validator, unknown_txid, 0, fetcher)
  end

  test "is_validated? returns false for unknown txid" do
    validator = Lineage.new(:binary.copy(<<0x01>>, 32), :binary.copy(<<0xAA>>, 20))
    assert Lineage.is_validated?(validator, :binary.copy(<<0x99>>, 32)) == false
  end

  test "validated_count starts at 1" do
    validator = Lineage.new(:binary.copy(<<0x01>>, 32), :binary.copy(<<0xAA>>, 20))
    assert Lineage.validated_count(validator) == 1
  end
end
