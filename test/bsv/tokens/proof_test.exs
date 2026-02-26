defmodule BSV.Tokens.ProofTest do
  use ExUnit.Case, async: true

  alias BSV.{Crypto, Transaction, PrivateKey, PublicKey}
  alias BSV.Transaction.{Input, Output}
  alias BSV.Tokens.Proof

  # Build a simple test transaction with known structure
  defp build_test_tx do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    addr = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, locking_script} = BSV.Script.Address.to_script(addr)

    tx = %Transaction{
      inputs: [
        %Input{
          source_txid: :binary.copy(<<0xAA>>, 32),
          source_tx_out_index: 0,
          unlocking_script: BSV.Script.new(),
          source_output: %Output{satoshis: 10000, locking_script: locking_script}
        }
      ],
      outputs: [
        %Output{satoshis: 5000, locking_script: locking_script},
        %Output{satoshis: 3000, locking_script: locking_script}
      ]
    }

    raw = Transaction.to_binary(tx)
    {tx, raw}
  end

  test "split and reconstruct vout 0" do
    {_tx, raw} = build_test_tx()
    assert {:ok, {prefix, output, suffix}} = Proof.split_tx_around_output(raw, 0)

    reconstructed = prefix <> output <> suffix
    assert Crypto.sha256d(reconstructed) == Crypto.sha256d(raw)
  end

  test "split and reconstruct vout 1" do
    {_tx, raw} = build_test_tx()
    assert {:ok, {prefix, output, suffix}} = Proof.split_tx_around_output(raw, 1)

    reconstructed = prefix <> output <> suffix
    assert Crypto.sha256d(reconstructed) == Crypto.sha256d(raw)
  end

  test "split vout out of range" do
    {_tx, raw} = build_test_tx()
    assert {:error, _} = Proof.split_tx_around_output(raw, 5)
  end

  test "split empty tx" do
    assert {:error, "raw TX too short"} = Proof.split_tx_around_output(<<>>, 0)
  end

  test "output bytes contain correct satoshis" do
    {_tx, raw} = build_test_tx()

    {:ok, {_prefix, output0, _suffix}} = Proof.split_tx_around_output(raw, 0)
    <<satoshis0::little-64, _rest::binary>> = output0
    assert satoshis0 == 5000

    {:ok, {_prefix, output1, _suffix}} = Proof.split_tx_around_output(raw, 1)
    <<satoshis1::little-64, _rest::binary>> = output1
    assert satoshis1 == 3000
  end

  test "varint roundtrip" do
    for val <- [0, 1, 0xFC, 0xFD, 0xFFFE, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000] do
      encoded = Proof.encode_varint(val)
      assert {:ok, {^val, _}} = Proof.read_varint(encoded, 0)
    end
  end

  test "read_varint truncated" do
    assert {:error, "truncated varint"} = Proof.read_varint(<<>>, 0)
    assert {:error, "truncated varint (fd)"} = Proof.read_varint(<<0xFD, 0x01>>, 0)
  end

  test "split truncated input data" do
    # Version + varint(1 input) but no input data
    truncated = <<0x01, 0x00, 0x00, 0x00, 0x01, 0xAA>>
    assert {:error, _} = Proof.split_tx_around_output(truncated, 0)
  end
end
