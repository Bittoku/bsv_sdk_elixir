defmodule BSV.Tokens.Factory.StasP2MPKHTest do
  use ExUnit.Case, async: true

  alias BSV.{PrivateKey, PublicKey, Crypto, Script}
  alias BSV.Tokens.Factory.Stas
  alias BSV.Tokens.{Payment, Destination, SigningKey}
  alias BSV.Transaction.P2MPKH

  defp gen_keys(n) do
    privs = for _ <- 1..n, do: PrivateKey.generate()

    pubs =
      Enum.map(privs, fn k ->
        PrivateKey.to_public_key(k) |> PublicKey.compress() |> Map.get(:point)
      end)

    {privs, pubs}
  end

  defp make_address_from_key(key) do
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    BSV.Base58.check_encode(pkh, 0x00)
  end

  defp make_p2pkh_script(address) do
    {:ok, script} = BSV.Script.Address.to_script(address)
    script
  end

  defp make_mpkh_address(multisig) do
    mpkh = P2MPKH.mpkh(multisig)
    BSV.Base58.check_encode(mpkh, 0x00)
  end

  describe "build_transfer_tx with P2MPKH signing key" do
    test "transfer succeeds with multi signing key on token input" do
      # Generate a 2-of-3 multisig for the token owner
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      owner_sk = SigningKey.multi(Enum.take(privs, 2), ms)

      # The token UTXO's address is the MPKH address
      owner_addr = make_mpkh_address(ms)
      owner_script = make_p2pkh_script(owner_addr)

      token_utxo = %Payment{
        txid: :binary.copy(<<0xAA>>, 32),
        vout: 0,
        satoshis: 1000,
        locking_script: owner_script,
        signing_key: owner_sk
      }

      # Funding uses a simple P2PKH key
      fund_key = PrivateKey.generate()
      fund_addr = make_address_from_key(fund_key)
      fund_script = make_p2pkh_script(fund_addr)

      funding = %Payment{
        txid: :binary.copy(<<0xBB>>, 32),
        vout: 0,
        satoshis: 50_000,
        locking_script: fund_script,
        private_key: fund_key
      }

      # Destination: transfer to a new P2PKH address
      dest_key = PrivateKey.generate()
      dest_addr = make_address_from_key(dest_key)
      dest = %Destination{address: dest_addr, satoshis: 1000}

      redemption_key = PrivateKey.generate()
      redemption_pubkey =
        PrivateKey.to_public_key(redemption_key) |> PublicKey.compress()
      redemption_pkh = Crypto.hash160(redemption_pubkey.point)

      config = %{
        token_utxo: token_utxo,
        destination: dest,
        redemption_pkh: redemption_pkh,
        splittable: true,
        funding: funding,
        fee_rate: 500
      }

      assert {:ok, tx} = Stas.build_transfer_tx(config)

      # Verify transaction structure
      assert length(tx.inputs) == 2
      # At least 1 token output + possibly change
      assert length(tx.outputs) >= 1

      # Verify all inputs have unlocking scripts set (not nil or empty)
      Enum.each(tx.inputs, fn input ->
        assert input.unlocking_script != nil
        assert %Script{} = input.unlocking_script
        assert input.unlocking_script.chunks != []
      end)

      # The token input (index 0) should have a multi-key unlocking script
      # It should have M sig chunks + 1 multisig script chunk
      token_unlock = Enum.at(tx.inputs, 0).unlocking_script
      assert %Script{chunks: chunks} = token_unlock
      # 2 sigs + 1 multisig script = 3 chunks
      assert length(chunks) == 3

      # Verify the last chunk is the serialized multisig script
      assert {:data, ms_bytes} = List.last(chunks)
      assert ms_bytes == P2MPKH.to_script_bytes(ms)

      # Token output should be present with correct satoshis
      token_output = hd(tx.outputs)
      assert token_output.satoshis == 1000
    end

    test "transfer with multi signing key on funding input" do
      # Token uses simple P2PKH
      token_key = PrivateKey.generate()
      token_addr = make_address_from_key(token_key)
      token_script = make_p2pkh_script(token_addr)

      token_utxo = %Payment{
        txid: :binary.copy(<<0xCC>>, 32),
        vout: 0,
        satoshis: 2000,
        locking_script: token_script,
        private_key: token_key
      }

      # Funding uses a 2-of-3 multisig
      {fund_privs, fund_pubs} = gen_keys(3)
      {:ok, fund_ms} = P2MPKH.new_multisig(2, fund_pubs)
      fund_sk = SigningKey.multi(Enum.take(fund_privs, 2), fund_ms)

      fund_addr = make_mpkh_address(fund_ms)
      fund_script = make_p2pkh_script(fund_addr)

      funding = %Payment{
        txid: :binary.copy(<<0xDD>>, 32),
        vout: 0,
        satoshis: 50_000,
        locking_script: fund_script,
        signing_key: fund_sk
      }

      dest_key = PrivateKey.generate()
      dest_addr = make_address_from_key(dest_key)
      dest = %Destination{address: dest_addr, satoshis: 2000}

      redemption_key = PrivateKey.generate()
      redemption_pubkey =
        PrivateKey.to_public_key(redemption_key) |> PublicKey.compress()
      redemption_pkh = Crypto.hash160(redemption_pubkey.point)

      config = %{
        token_utxo: token_utxo,
        destination: dest,
        redemption_pkh: redemption_pkh,
        splittable: false,
        funding: funding,
        fee_rate: 500
      }

      assert {:ok, tx} = Stas.build_transfer_tx(config)

      # Both inputs should be signed
      Enum.each(tx.inputs, fn input ->
        assert input.unlocking_script != nil
        assert input.unlocking_script.chunks != []
      end)

      # Change output (if present) should derive from the MPKH
      if length(tx.outputs) > 1 do
        change_output = List.last(tx.outputs)
        change_script_bin = Script.to_binary(change_output.locking_script)

        # P2PKH locking script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        # Extract the 20-byte hash (bytes 3..22)
        <<_::binary-size(3), pkh::binary-size(20), _::binary>> = change_script_bin

        # The change address PKH should be the MPKH of the funding multisig
        expected_mpkh = P2MPKH.mpkh(fund_ms)
        assert pkh == expected_mpkh
      end
    end
  end
end
