defmodule BSV.Tokens.Script.ReaderTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Reader
  alias BSV.Tokens.Script.StasBuilder
  alias BSV.Tokens.Script.Stas3Builder

  defp build_stas_script(owner, redemption, splittable) do
    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, splittable)
    BSV.Script.to_binary(script)
  end

  test "classify STAS v2" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)
    script_bin = build_stas_script(owner, redemption, true)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :stas
    assert parsed.stas.owner_hash == owner
    assert parsed.stas.redemption_hash == redemption
  end

  test "classify P2PKH" do
    {:ok, script_bin} =
      Base.decode16("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac", case: :mixed)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :p2pkh
    assert parsed.stas == nil
  end

  test "classify OP_RETURN" do
    {:ok, script_bin} = Base.decode16("6a0568656c6c6f", case: :mixed)
    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :op_return
  end

  test "classify OP_FALSE OP_RETURN" do
    {:ok, script_bin} = Base.decode16("006a0568656c6c6f", case: :mixed)
    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :op_return
  end

  test "classify unknown" do
    parsed = Reader.read_locking_script(<<0xFF, 0xFE, 0xFD>>)
    assert parsed.script_type == :unknown
  end

  test "classify empty" do
    parsed = Reader.read_locking_script(<<>>)
    assert parsed.script_type == :unknown
  end

  test "is_stas true" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)
    script_bin = build_stas_script(owner, redemption, true)
    assert Reader.is_stas(script_bin) == true
  end

  test "is_stas false for P2PKH" do
    {:ok, script_bin} =
      Base.decode16("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac", case: :mixed)

    assert Reader.is_stas(script_bin) == false
  end

  test "is_stas false for empty" do
    assert Reader.is_stas(<<>>) == false
  end

  test "STAS v2 extracts token_id" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)
    script_bin = build_stas_script(owner, redemption, true)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.stas.token_id.pkh == redemption
  end

  test "STAS v2 extracts flags splittable" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)
    script_bin = build_stas_script(owner, redemption, true)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.stas.flags == <<0x00>>
  end

  test "STAS v2 extracts flags non-splittable" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)
    script_bin = build_stas_script(owner, redemption, false)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.stas.flags == <<0x01>>
  end

  test "garbage bytes no panic" do
    for len <- 0..50 do
      script = :binary.list_to_bin(for i <- 0..(len - 1)//1, do: rem(i * 7 + 3, 256))
      Reader.read_locking_script(script)
      Reader.is_stas(script)
    end
  end

  test "classify STAS3 unfrozen" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner, redemption, nil, false, true, [], [])

    script_bin = BSV.Script.to_binary(script)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :stas3
    assert parsed.stas3.owner == owner
    assert parsed.stas3.redemption == redemption
    assert parsed.stas3.frozen == false
  end

  test "classify STAS3 frozen" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner, redemption, nil, true, true, [], [])

    script_bin = BSV.Script.to_binary(script)

    parsed = Reader.read_locking_script(script_bin)
    assert parsed.script_type == :stas3
    assert parsed.stas3.frozen == true
  end

  # STAS 3.0 v0.1 §9.5 / §10.3 — arbitrator-free / signature-suppression sentinel.
  test "arbitrator_free_owner? true when STAS3 owner is EMPTY_HASH160" do
    empty = BSV.Tokens.Script.Templates.empty_hash160()
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(empty, redemption, nil, false, true, [], [])

    script_bin = BSV.Script.to_binary(script)
    assert Reader.arbitrator_free_owner?(script_bin) == true
    assert Reader.arbitrator_free_owner?(script) == true

    parsed = Reader.read_locking_script(script_bin)
    assert Reader.arbitrator_free_owner?(parsed) == true
    assert Reader.arbitrator_free_owner?(parsed.stas3) == true

    # And EMPTY_HASH160 hex matches the spec sentinel.
    assert Base.encode16(empty, case: :lower) == "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
  end

  test "arbitrator_free_owner? false for normal STAS3 owner" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} =
      Stas3Builder.build_stas3_locking_script(owner, redemption, nil, false, true, [], [])

    refute Reader.arbitrator_free_owner?(BSV.Script.to_binary(script))
  end

  # STAS 3.0 v0.1 §10.2 — positive P2MPKH classification.
  # Round-trip the canonical 70-byte P2MPKH locking script through the reader
  # and assert it is classified as `:p2mpkh`.
  test "classify P2MPKH (STAS 3.0 v0.1 §10.2 fixed 70-byte body)" do
    mpkh = :binary.copy(<<0xAB>>, 20)
    bin = BSV.Tokens.Script.Templates.p2mpkh_locking_script(mpkh)
    assert byte_size(bin) == 70

    parsed = Reader.read_locking_script(bin)
    assert parsed.script_type == :p2mpkh
    assert parsed.stas == nil
    assert parsed.stas3 == nil
  end

  test "classify P2MPKH for a real 3-of-5 redeem buffer's MPKH" do
    pk = fn b -> <<0x02, :binary.copy(<<b>>, 32)::binary>> end
    pubs = [pk.(0x01), pk.(0x02), pk.(0x03), pk.(0x04), pk.(0x05)]
    {:ok, ms} = BSV.Transaction.P2MPKH.new_multisig(3, pubs)

    mpkh = BSV.Transaction.P2MPKH.mpkh(ms)
    bin = BSV.Tokens.Script.Templates.p2mpkh_locking_script(mpkh)

    parsed = Reader.read_locking_script(bin)
    assert parsed.script_type == :p2mpkh
  end

  test "arbitrator_free_owner? false for non-STAS3 inputs" do
    refute Reader.arbitrator_free_owner?(
             <<0x76, 0xA9, 0x14>> <> :binary.copy(<<0xAA>>, 20) <> <<0x88, 0xAC>>
           )

    refute Reader.arbitrator_free_owner?(<<>>)
  end
end
