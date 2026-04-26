defmodule BSV.Tokens.Template.StasP2MPKHTest do
  use ExUnit.Case, async: true

  alias BSV.{Script, PrivateKey, PublicKey, Crypto}
  alias BSV.Transaction
  alias BSV.Transaction.{Input, Output, P2MPKH}
  alias BSV.Tokens.Template.Stas, as: StasTemplate
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

  describe "unlock_mpkh/3" do
    test "creates a %Stas{} struct with multi signing key" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      template = StasTemplate.unlock_mpkh(Enum.take(privs, 2), ms)

      assert %StasTemplate{} = template
      assert {:multi, keys, multisig} = template.signing_key
      assert length(keys) == 2
      assert multisig.threshold == 2
      assert length(multisig.public_keys) == 3
      assert template.sighash_flag == 0x41
      assert template.spend_type == nil
    end

    test "accepts spend_type option" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = StasTemplate.unlock_mpkh(Enum.take(privs, 1), ms, spend_type: :transfer)

      assert template.spend_type == :transfer
    end

    test "accepts sighash_flag option" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = StasTemplate.unlock_mpkh(Enum.take(privs, 1), ms, sighash_flag: 0x01)

      assert template.sighash_flag == 0x01
    end
  end

  # -- unlock_from_signing_key tests --

  describe "unlock_from_signing_key/2 with multi key" do
    test "creates struct from a multi SigningKey" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      sk = SigningKey.multi(Enum.take(privs, 2), ms)
      template = StasTemplate.unlock_from_signing_key(sk)

      assert %StasTemplate{} = template
      assert {:multi, _, _} = template.signing_key
      assert template.sighash_flag == 0x41
    end

    test "passes options through" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      sk = SigningKey.multi(Enum.take(privs, 1), ms)

      template =
        StasTemplate.unlock_from_signing_key(sk, spend_type: :transfer, sighash_flag: 0x01)

      assert template.spend_type == :transfer
      assert template.sighash_flag == 0x01
    end
  end

  # -- sign/3 with multi key --

  describe "sign/3 with P2MPKH" do
    test "produces script with M signature chunks + multisig script chunk (2-of-3)" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      signing_keys = Enum.take(privs, 2)
      template = StasTemplate.unlock_mpkh(signing_keys, ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 5000)

      assert {:ok, %Script{chunks: chunks}} = StasTemplate.sign(template, tx, 0)

      # 2 signature chunks + 1 multisig script chunk = 3 total
      assert length(chunks) == 3

      # First M chunks are signatures
      sig_chunks = Enum.take(chunks, 2)

      Enum.each(sig_chunks, fn chunk ->
        assert {:data, sig_bytes} = chunk
        # DER sig (70-72 bytes) + 1 sighash flag = 71-73 bytes
        assert byte_size(sig_bytes) >= 70
        assert byte_size(sig_bytes) <= 73
        # Last byte is the sighash flag
        assert :binary.last(sig_bytes) == 0x41
      end)

      # Last chunk is the serialized multisig script
      assert {:data, ms_bytes} = List.last(chunks)
      assert ms_bytes == P2MPKH.to_script_bytes(ms)
    end

    test "produces script with 1 signature chunk for 1-of-1" do
      {privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = StasTemplate.unlock_mpkh(privs, ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 1000)

      assert {:ok, %Script{chunks: chunks}} = StasTemplate.sign(template, tx, 0)
      # 1 sig + 1 multisig script = 2
      assert length(chunks) == 2

      assert {:data, sig_bytes} = hd(chunks)
      assert byte_size(sig_bytes) >= 70
      assert :binary.last(sig_bytes) == 0x41

      assert {:data, ms_bytes} = List.last(chunks)
      assert ms_bytes == P2MPKH.to_script_bytes(ms)
    end

    test "produces script with 3 signature chunks for 3-of-5" do
      {privs, pubs} = gen_keys(5)
      {:ok, ms} = P2MPKH.new_multisig(3, pubs)
      signing_keys = Enum.take(privs, 3)
      template = StasTemplate.unlock_mpkh(signing_keys, ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 10000)

      assert {:ok, %Script{chunks: chunks}} = StasTemplate.sign(template, tx, 0)
      # 3 sigs + 1 multisig script = 4
      assert length(chunks) == 4

      sig_chunks = Enum.take(chunks, 3)

      Enum.each(sig_chunks, fn {:data, sig_bytes} ->
        assert byte_size(sig_bytes) >= 70
        assert byte_size(sig_bytes) <= 73
        assert :binary.last(sig_bytes) == 0x41
      end)

      assert {:data, ms_bytes} = List.last(chunks)
      assert ms_bytes == P2MPKH.to_script_bytes(ms)
    end

    test "each signature is unique (different keys produce different sigs)" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      signing_keys = Enum.take(privs, 2)
      template = StasTemplate.unlock_mpkh(signing_keys, ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 5000)

      {:ok, %Script{chunks: chunks}} = StasTemplate.sign(template, tx, 0)
      [{:data, sig1}, {:data, sig2} | _] = chunks

      # Two different keys should produce different signatures
      assert sig1 != sig2
    end

    test "returns error when source_output is missing" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = StasTemplate.unlock_mpkh(Enum.take(privs, 1), ms)

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

      assert {:error, :missing_source_output} = StasTemplate.sign(template, tx, 0)
    end
  end

  # -- estimate_length/3 --

  describe "estimate_length/3 for multi path (STAS 3.0 v0.1 §10.2)" do
    test "2-of-3: m*73 + 34*n + 5" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      template = StasTemplate.unlock_mpkh(Enum.take(privs, 2), ms)

      expected = 2 * 73 + 34 * 3 + 5
      assert StasTemplate.estimate_length(template, nil, nil) == expected
    end

    test "1-of-1: m*73 + 34*n + 5" do
      {privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      template = StasTemplate.unlock_mpkh(privs, ms)

      expected = 1 * 73 + 34 * 1 + 5
      assert StasTemplate.estimate_length(template, nil, nil) == expected
    end

    test "3-of-5: m*73 + 34*n + 5" do
      {privs, pubs} = gen_keys(5)
      {:ok, ms} = P2MPKH.new_multisig(3, pubs)
      template = StasTemplate.unlock_mpkh(Enum.take(privs, 3), ms)

      expected = 3 * 73 + 34 * 5 + 5
      assert StasTemplate.estimate_length(template, nil, nil) == expected
    end

    test "multi estimate exceeds single P2PKH estimate" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      multi_template = StasTemplate.unlock_mpkh(Enum.take(privs, 2), ms)

      single_key = PrivateKey.generate()
      single_template = StasTemplate.unlock(single_key)

      assert StasTemplate.estimate_length(multi_template, nil, nil) >
               StasTemplate.estimate_length(single_template, nil, nil)
    end
  end
end
