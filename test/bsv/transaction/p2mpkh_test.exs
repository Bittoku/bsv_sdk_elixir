defmodule BSV.Transaction.P2MPKHTest do
  use ExUnit.Case, async: true

  alias BSV.Transaction.P2MPKH
  alias BSV.{Crypto, PrivateKey, PublicKey}

  # Deterministic 33-byte compressed public keys for snapshot vectors.
  # These are the canonical i*G (i = 1..5) compressed SEC1 encodings —
  # convenient because they don't depend on randomness and align with the
  # cross-SDK reference vector in `bsv-sdk-rust` at
  # `crates/bsv-transaction/src/template/p2mpkh.rs::deterministic_3_of_5_redeem_vector`.
  # Both SDKs MUST produce identical 172-byte redeem buffers and identical
  # MPKH for these inputs.
  @pk1 <<0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
         0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
         0xF8, 0x17, 0x98>>
  @pk2 <<0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0,
         0x7C, 0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C,
         0x70, 0x9E, 0xE5>>
  @pk3 <<0x02, 0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
         0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13, 0xBC,
         0xE0, 0x36, 0xF9>>
  @pk4 <<0x02, 0xE4, 0x93, 0xDB, 0xF1, 0xC1, 0x0D, 0x80, 0xF3, 0x58, 0x1E, 0x49, 0x04, 0x93, 0x0B,
         0x14, 0x04, 0xCC, 0x6C, 0x13, 0x90, 0x0E, 0xE0, 0x75, 0x84, 0x74, 0xFA, 0x94, 0xAB, 0xE8,
         0xC4, 0xCD, 0x13>>
  @pk5 <<0x02, 0x2F, 0x8B, 0xDE, 0x4D, 0x1A, 0x07, 0x20, 0x93, 0x55, 0xB4, 0xA7, 0x25, 0x0A, 0x5C,
         0x51, 0x28, 0xE8, 0x8B, 0x84, 0xBD, 0xDC, 0x61, 0x9A, 0xB7, 0xCB, 0xA8, 0xD5, 0x69, 0xB2,
         0x40, 0xEF, 0xE4>>

  defp gen_keys(n) do
    privs = for _ <- 1..n, do: PrivateKey.generate()

    pubs =
      Enum.map(privs, fn k ->
        PrivateKey.to_public_key(k) |> PublicKey.compress() |> Map.get(:point)
      end)

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

    test "rejects too many keys (spec cap is 5)" do
      {_privs, pubs} = gen_keys(6)
      assert {:error, {:too_many_keys, 6}} = P2MPKH.new_multisig(1, pubs)
    end

    test "rejects non-33-byte keys" do
      assert {:error, :invalid_public_key_size} = P2MPKH.new_multisig(1, [<<1, 2, 3>>])
    end
  end

  describe "to_script_bytes/1 and from_script_bytes/1 (STAS 3.0 v0.1 §10.2)" do
    test "roundtrip 2-of-3" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      bytes = P2MPKH.to_script_bytes(ms)
      # Spec wire length = 2 + 34*N
      assert byte_size(bytes) == 2 + 34 * 3
      assert {:ok, ms2} = P2MPKH.from_script_bytes(bytes)
      assert ms2.threshold == 2
      assert length(ms2.public_keys) == 3
      assert ms2.public_keys == pubs
    end

    test "roundtrip 1-of-1, length 36" do
      {_privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      bytes = P2MPKH.to_script_bytes(ms)
      # Spec wire length = 2 + 34*1 = 36
      assert byte_size(bytes) == 36
      assert {:ok, ms2} = P2MPKH.from_script_bytes(bytes)
      assert ms2.threshold == 1
      assert ms2.public_keys == pubs
    end

    test "deterministic 3-of-5 snapshot vector matches spec format and is 172 bytes" do
      pubs = [@pk1, @pk2, @pk3, @pk4, @pk5]
      {:ok, ms} = P2MPKH.new_multisig(3, pubs)
      bytes = P2MPKH.to_script_bytes(ms)

      # 1 (m) + 5 * (1 + 33) (key pushes) + 1 (n) = 172
      assert byte_size(bytes) == 172

      # Leading byte = m raw (0x03), trailing byte = n raw (0x05).
      # NOT OP_3 (0x53) and NOT OP_5 (0x55), and NO trailing 0xAE.
      assert <<m::8, body::binary-size(170), n::8>> = bytes
      assert m == 0x03
      assert n == 0x05

      # Each key is preceded by 0x21 length-prefix.
      expected_body =
        Enum.reduce([@pk1, @pk2, @pk3, @pk4, @pk5], <<>>, fn pk, acc ->
          acc <> <<0x21, pk::binary>>
        end)

      assert body == expected_body

      expected_hex =
        "03" <>
          Enum.map_join([@pk1, @pk2, @pk3, @pk4, @pk5], "", fn pk ->
            "21" <> Base.encode16(pk, case: :lower)
          end) <>
          "05"

      assert Base.encode16(bytes, case: :lower) == expected_hex

      # Hard-coded canonical hex pinned to the Rust SDK reference vector at
      # bsv-sdk-rust/crates/bsv-transaction/src/template/p2mpkh.rs.
      # Drift here means an @pkN constant changed; cross-SDK MPKH will diverge.
      canonical_hex =
        "03" <>
          "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" <>
          "2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" <>
          "2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" <>
          "2102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13" <>
          "21022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4" <>
          "05"

      assert Base.encode16(bytes, case: :lower) == canonical_hex

      # MPKH = HASH160(redeem_buffer); pinned for cross-SDK parity check.
      assert Base.encode16(P2MPKH.mpkh(ms), case: :lower) ==
               "deb7bfb8b45c2bfe4579af5126b46c4d95e4e3a6"

      # Round-trip parse
      assert {:ok, ms2} = P2MPKH.from_script_bytes(bytes)
      assert ms2.threshold == 3
      assert ms2.public_keys == pubs
    end

    test "1-of-1 deterministic vector is exact bytes" do
      {:ok, ms} = P2MPKH.new_multisig(1, [@pk1])
      bytes = P2MPKH.to_script_bytes(ms)
      pk1 = @pk1
      assert bytes == <<0x01, 0x21, pk1::binary, 0x01>>
      assert byte_size(bytes) == 36
    end

    test "rejects garbage" do
      assert {:error, _} = P2MPKH.from_script_bytes(<<0x00, 0x01, 0x02>>)
    end

    test "rejects legacy OP_m form (no longer supported)" do
      pk1 = @pk1
      pk2 = @pk2
      pk3 = @pk3
      # Legacy: <<OP_2, 0x21, pk1, 0x21, pk2, 0x21, pk3, OP_3, OP_CHECKMULTISIG>>
      legacy =
        <<0x52, 0x21, pk1::binary, 0x21, pk2::binary, 0x21, pk3::binary, 0x53, 0xAE>>

      # OP_2 = 0x52 = 82, exceeds @max_keys=5, must be rejected.
      assert {:error, _} = P2MPKH.from_script_bytes(legacy)
    end

    test "rejects out-of-range threshold (>5)" do
      pk1 = @pk1

      assert {:error, {:invalid_threshold, _}} =
               P2MPKH.from_script_bytes(<<0x06, 0x21, pk1::binary, 0x01>>)
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

    test "equals HASH160 of script bytes (round-trip)" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      bytes = P2MPKH.to_script_bytes(ms)
      assert P2MPKH.mpkh(ms) == Crypto.hash160(bytes)
      # And the buffer parses back to the same multisig
      assert {:ok, ^ms} = P2MPKH.from_script_bytes(bytes)
    end
  end

  describe "lock/1" do
    test "wraps the redeem buffer as a single data-push chunk" do
      {_privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      assert {:ok, %BSV.Script{chunks: [{:data, body}]}} = P2MPKH.lock(ms)
      assert body == P2MPKH.to_script_bytes(ms)
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
    test "2-of-3 estimate matches m*73 + 34*n + 5" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 2), ms)
      est = P2MPKH.estimate_length(unlocker, nil, nil)
      assert est == 2 * 73 + 34 * 3 + 5
    end

    test "1-of-1 estimate" do
      {privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      {:ok, unlocker} = P2MPKH.unlock(privs, ms)
      est = P2MPKH.estimate_length(unlocker, nil, nil)
      assert est == 1 * 73 + 34 * 1 + 5
    end

    test "3-of-5 estimate" do
      {privs, pubs} = gen_keys(5)
      {:ok, ms} = P2MPKH.new_multisig(3, pubs)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 3), ms)
      est = P2MPKH.estimate_length(unlocker, nil, nil)
      assert est == 3 * 73 + 34 * 5 + 5
    end
  end

  describe "sign/3 (P2MPKH spend, OP_0 + sigs + redeem buffer)" do
    defp make_p2pkh_locking_script do
      key = PrivateKey.generate()
      pubkey = PrivateKey.to_public_key(key) |> PublicKey.compress()
      pkh = Crypto.hash160(pubkey.point)
      addr = BSV.Base58.check_encode(pkh, 0x00)
      {:ok, script} = BSV.Script.Address.to_script(addr)
      script
    end

    defp mock_tx_with_source(locking_script, satoshis) do
      source_output = %BSV.Transaction.Output{
        satoshis: satoshis,
        locking_script: locking_script
      }

      input = %BSV.Transaction.Input{
        source_txid: :crypto.strong_rand_bytes(32),
        source_tx_out_index: 0,
        source_output: source_output,
        unlocking_script: BSV.Script.new()
      }

      %BSV.Transaction{inputs: [input], outputs: [], version: 1, lock_time: 0}
    end

    test "2-of-3 produces OP_0 + 2 sigs + redeem buffer (4 chunks)" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 2), ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 5000)

      assert {:ok, %BSV.Script{chunks: chunks}} = P2MPKH.sign(unlocker, tx, 0)

      # OP_0 + 2 sigs + redeem buffer = 4 chunks
      assert length(chunks) == 4
      # First chunk is OP_0
      assert {:data, <<>>} = hd(chunks)
      # Last chunk is the redeem buffer
      assert {:data, redeem} = List.last(chunks)
      assert redeem == P2MPKH.to_script_bytes(ms)

      # Middle chunks are DER sigs
      [_op0 | rest] = chunks
      sig_chunks = Enum.take(rest, 2)

      Enum.each(sig_chunks, fn {:data, sig_bytes} ->
        assert byte_size(sig_bytes) >= 70
        assert byte_size(sig_bytes) <= 73
        assert :binary.last(sig_bytes) == 0x41
      end)
    end

    test "1-of-1 produces OP_0 + 1 sig + redeem buffer (3 chunks)" do
      {privs, pubs} = gen_keys(1)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      {:ok, unlocker} = P2MPKH.unlock(privs, ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 1000)

      assert {:ok, %BSV.Script{chunks: chunks}} = P2MPKH.sign(unlocker, tx, 0)

      # OP_0 + 1 sig + redeem buffer = 3 chunks
      assert length(chunks) == 3
      assert {:data, <<>>} = hd(chunks)
      assert {:data, redeem} = List.last(chunks)
      assert redeem == P2MPKH.to_script_bytes(ms)
    end

    test "3-of-5 produces OP_0 + 3 sigs + redeem buffer (5 chunks)" do
      {privs, pubs} = gen_keys(5)
      {:ok, ms} = P2MPKH.new_multisig(3, pubs)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 3), ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 10000)

      assert {:ok, %BSV.Script{chunks: chunks}} = P2MPKH.sign(unlocker, tx, 0)

      assert length(chunks) == 5
      assert {:data, <<>>} = hd(chunks)
      assert {:data, redeem} = List.last(chunks)
      assert redeem == P2MPKH.to_script_bytes(ms)
      assert byte_size(redeem) == 172
    end

    test "each signature is unique (different keys)" do
      {privs, pubs} = gen_keys(3)
      {:ok, ms} = P2MPKH.new_multisig(2, pubs)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 2), ms)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 5000)

      {:ok, %BSV.Script{chunks: chunks}} = P2MPKH.sign(unlocker, tx, 0)
      [_op0, {:data, sig1}, {:data, sig2}, _redeem] = chunks
      assert sig1 != sig2
    end

    test "returns error when source_output is nil" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 1), ms)

      tx = %BSV.Transaction{
        inputs: [
          %BSV.Transaction.Input{
            source_txid: :crypto.strong_rand_bytes(32),
            source_tx_out_index: 0,
            source_output: nil
          }
        ],
        outputs: []
      }

      assert {:error, :missing_source_output} = P2MPKH.sign(unlocker, tx, 0)
    end

    test "sign with custom sighash_flag (SIGHASH_NONE | FORKID)" do
      {privs, pubs} = gen_keys(2)
      {:ok, ms} = P2MPKH.new_multisig(1, pubs)
      # 0x42 = SIGHASH_NONE (0x02) | SIGHASH_FORKID (0x40)
      {:ok, unlocker} = P2MPKH.unlock(Enum.take(privs, 1), ms, sighash_flag: 0x42)

      locking = make_p2pkh_locking_script()
      tx = mock_tx_with_source(locking, 2000)

      assert {:ok, %BSV.Script{chunks: chunks}} = P2MPKH.sign(unlocker, tx, 0)
      [_op0, {:data, sig_bytes}, _redeem] = chunks
      assert :binary.last(sig_bytes) == 0x42
    end
  end
end
