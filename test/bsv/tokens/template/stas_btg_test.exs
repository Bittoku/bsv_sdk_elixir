defmodule BSV.Tokens.Template.StasBtgTest do
  use ExUnit.Case, async: true

  alias BSV.{Crypto, Script, Transaction, PrivateKey, PublicKey}
  alias BSV.Transaction.{Input, Output}
  alias BSV.Tokens.Template.{StasBtg, StasBtgCheckpoint}

  defp build_prev_tx do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    addr = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, locking} = BSV.Script.Address.to_script(addr)

    tx = %Transaction{
      inputs: [
        %Input{
          source_txid: :binary.copy(<<0xCC>>, 32),
          source_tx_out_index: 0,
          unlocking_script: Script.new(),
          source_output: %Output{satoshis: 10000, locking_script: locking}
        }
      ],
      outputs: [%Output{satoshis: 10000, locking_script: locking}]
    }

    raw = Transaction.to_binary(tx)
    {tx, raw, locking}
  end

  defp build_spending_tx(locking) do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    addr = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, out_script} = BSV.Script.Address.to_script(addr)

    tx = %Transaction{
      inputs: [
        %Input{
          source_txid: :binary.copy(<<0xDD>>, 32),
          source_tx_out_index: 0,
          source_output: %Output{satoshis: 10000, locking_script: locking}
        }
      ],
      outputs: [%Output{satoshis: 10000, locking_script: out_script}]
    }

    tx
  end

  test "BTG unlocking script ends with OP_TRUE" do
    {_prev_tx, prev_raw, locking} = build_prev_tx()
    key = PrivateKey.generate()
    tx = build_spending_tx(locking)

    template = StasBtg.unlock(key, prev_raw, 0)
    {:ok, unlocking} = StasBtg.sign(template, tx, 0)
    bytes = Script.to_binary(unlocking)

    assert byte_size(bytes) > 0
    assert :binary.last(bytes) == 0x51
  end

  test "BTG unlocking script longer than P2PKH" do
    {_prev_tx, prev_raw, locking} = build_prev_tx()
    key = PrivateKey.generate()
    tx = build_spending_tx(locking)

    template = StasBtg.unlock(key, prev_raw, 0)
    {:ok, unlocking} = StasBtg.sign(template, tx, 0)
    bytes = Script.to_binary(unlocking)

    assert byte_size(bytes) > 106
  end

  test "checkpoint unlocking script ends with OP_FALSE" do
    {_prev_tx, _prev_raw, locking} = build_prev_tx()
    owner_key = PrivateKey.generate()
    issuer_key = PrivateKey.generate()
    tx = build_spending_tx(locking)

    template = StasBtgCheckpoint.unlock(owner_key, issuer_key)
    {:ok, unlocking} = StasBtgCheckpoint.sign(template, tx, 0)
    bytes = Script.to_binary(unlocking)

    assert byte_size(bytes) > 0
    # OP_FALSE is encoded as OP_0 which is 0x00
    assert :binary.last(bytes) == 0x00
  end

  test "checkpoint unlocking script ~217 bytes" do
    {_prev_tx, _prev_raw, locking} = build_prev_tx()
    owner_key = PrivateKey.generate()
    issuer_key = PrivateKey.generate()
    tx = build_spending_tx(locking)

    template = StasBtgCheckpoint.unlock(owner_key, issuer_key)
    {:ok, unlocking} = StasBtgCheckpoint.sign(template, tx, 0)
    bytes = Script.to_binary(unlocking)

    assert byte_size(bytes) > 200 and byte_size(bytes) < 250
  end

  test "estimate_length accounts for prev tx" do
    {_prev_tx, prev_raw, _locking} = build_prev_tx()
    key = PrivateKey.generate()

    template = StasBtg.unlock(key, prev_raw, 0)
    estimated = StasBtg.estimate_length(template, %Transaction{}, 0)

    assert estimated >= 107 + byte_size(prev_raw)
  end

  test "sign fails for missing source output" do
    key = PrivateKey.generate()

    tx = %Transaction{
      inputs: [
        %Input{
          source_txid: :binary.copy(<<0xDD>>, 32),
          source_tx_out_index: 0,
          source_output: nil
        }
      ],
      outputs: []
    }

    template = StasBtg.unlock(key, <<>>, 0)
    assert {:error, :missing_source_output} = StasBtg.sign(template, tx, 0)
  end
end
