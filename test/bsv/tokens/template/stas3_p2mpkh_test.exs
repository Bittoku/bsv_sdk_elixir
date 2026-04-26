defmodule BSV.Tokens.Template.Stas3P2MPKHTest do
  use ExUnit.Case, async: true

  alias BSV.{Script, PrivateKey, PublicKey, Crypto}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2MPKH}
  alias BSV.Tokens.Template.Stas3, as: Stas3Template
  alias BSV.Tokens.SigningKey

  # -- Helpers --

  defp gen_keys(n) do
    privs = for _ <- 1..n, do: PrivateKey.generate()

    pubs =
      Enum.map(privs, fn k ->
        PrivateKey.to_public_key(k) |> PublicKey.compress() |> Map.get(:point)
      end)

    {privs, pubs}
  end

  defp make_p2pkh_locking_script do
    key = PrivateKey.generate()
    pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
    pkh = Crypto.hash160(pubkey.point)
    addr = BSV.Base58.check_encode(pkh, 0x00)
    {:ok, script} = BSV.Script.Address.to_script(addr)
    script
  end

  defp mock_tx_with_source(locking_script, satoshis) do
    source_output = %Output{
      satoshis: satoshis,
      locking_script: locking_script
    }

    input = %Input{
      source_txid: :crypto.strong_rand_bytes(32),
      source_tx_out_index: 0,
      source_output: source_output,
      unlocking_script: Script.new()
    }

    %Transaction{inputs: [input], outputs: [], version: 1, lock_time: 0}
  end

  # -- unlock_mpkh tests --

  describe "unlock_mpkh/4" do
    test "creates a %Stas3{} struct with multi signing key and spend_type" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      template = Stas3Template.unlock_mpkh(Enum.take(privs, 2), ms, :transfer)

      assert %Stas3Template{} = template
      assert {:multi, keys, multisig} = template.signing_key
      assert length(keys) == 2
      assert multisig.threshold == 2
      assert length(multisig.public_keys) == 3
      assert template.spend_type == :transfer
      assert template.sighash_flag == 0x41
    end

    test "accepts sighash_flag option" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)

      template =
        Stas3Template.unlock_mpkh(Enum.take(privs, 1), ms, :freeze_unfreeze, sighash_flag: 0x01)

      assert template.sighash_flag == 0x01
      assert template.spend_type == :freeze_unfreeze
    end
  end

  # -- unlock_from_signing_key tests --

  describe "unlock_from_signing_key/3 with multi key" do
    test "creates struct from a multi SigningKey" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      sk = SigningKey.multi(Enum.take(privs, 2), ms)
      template = Stas3Template.unlock_from_signing_key(sk, :transfer)

      assert %Stas3Template{} = template
      assert {:multi, _, _} = template.signing_key
      assert template.spend_type == :transfer
    end
  end

  # -- sign/3 with multi key --

  describe "sign/3 with P2MPKH (STAS 3.0 v0.1 §10.2 OP_0 + sigs + redeem buffer)" do
    test "produces script with OP_0 + M sig chunks + redeem buffer (2-of-3)" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      signing_keys = Enum.take(privs, 2)
      template = Stas3Template.unlock_mpkh(signing_keys, ms, :transfer)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 5000)

      assert {:ok, %Script{chunks: chunks}} = Stas3Template.sign(template, tx, 0)

      # OP_0 + 2 sigs + 1 redeem buffer = 4
      assert length(chunks) == 4
      assert {:data, <<>>} = hd(chunks)

      [_op0 | rest] = chunks
      sig_chunks = Enum.take(rest, 2)

      Enum.each(sig_chunks, fn chunk ->
        assert {:data, sig_bytes} = chunk
        assert byte_size(sig_bytes) >= 70
        assert byte_size(sig_bytes) <= 73
        assert :binary.last(sig_bytes) == 0x41
      end)

      # Last chunk is serialized redeem buffer
      assert {:data, ms_bytes} = List.last(chunks)
      assert ms_bytes == P2MPKH.to_script_bytes(ms)
    end

    test "produces script with OP_0 + 1 sig chunk + redeem buffer for 1-of-1" do
      {privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = Stas3Template.unlock_mpkh(privs, ms, :transfer)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 1000)

      assert {:ok, %Script{chunks: chunks}} = Stas3Template.sign(template, tx, 0)
      assert length(chunks) == 3
      assert {:data, <<>>} = hd(chunks)

      [_op0, {:data, sig_bytes}, _redeem] = chunks
      assert byte_size(sig_bytes) >= 70
      assert :binary.last(sig_bytes) == 0x41

      assert {:data, ms_bytes} = List.last(chunks)
      assert ms_bytes == P2MPKH.to_script_bytes(ms)
    end

    test "each signature is unique (different keys produce different sigs)" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      signing_keys = Enum.take(privs, 2)
      template = Stas3Template.unlock_mpkh(signing_keys, ms, :transfer)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 5000)

      {:ok, %Script{chunks: chunks}} = Stas3Template.sign(template, tx, 0)
      [_op0, {:data, sig1}, {:data, sig2} | _] = chunks
      assert sig1 != sig2
    end

    test "returns error when source_output is missing" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = Stas3Template.unlock_mpkh(Enum.take(privs, 1), ms, :transfer)

      tx = %Transaction{
        inputs: [
          %Input{
            source_txid: :crypto.strong_rand_bytes(32),
            source_tx_out_index: 0,
            source_output: nil
          }
        ],
        outputs: []
      }

      assert {:error, :missing_source_output} = Stas3Template.sign(template, tx, 0)
    end
  end

  # -- estimate_length/3 --

  describe "estimate_length/3 for multi path (STAS 3.0 v0.1 §10.2)" do
    test "2-of-3: m*73 + 34*n + 5" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      template = Stas3Template.unlock_mpkh(Enum.take(privs, 2), ms, :transfer)

      expected = 2 * 73 + 34 * 3 + 5
      assert Stas3Template.estimate_length(template, nil, nil) == expected
    end

    test "1-of-1: m*73 + 34*n + 5" do
      {privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = Stas3Template.unlock_mpkh(privs, ms, :transfer)

      expected = 1 * 73 + 34 * 1 + 5
      assert Stas3Template.estimate_length(template, nil, nil) == expected
    end

    test "3-of-5: m*73 + 34*n + 5" do
      {privs, pubs} = gen_keys(5)
      {:ok, ms} = P2MPKH.new_multisig(3, pubs)
      template = Stas3Template.unlock_mpkh(Enum.take(privs, 3), ms, :transfer)

      expected = 3 * 73 + 34 * 5 + 5
      assert Stas3Template.estimate_length(template, nil, nil) == expected
    end

    test "multi estimate exceeds single P2PKH estimate" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      multi_template = Stas3Template.unlock_mpkh(Enum.take(privs, 2), ms, :transfer)

      single_key = PrivateKey.generate()
      single_template = Stas3Template.unlock(single_key, :transfer)

      assert Stas3Template.estimate_length(multi_template, nil, nil) >
               Stas3Template.estimate_length(single_template, nil, nil)
    end
  end
end
