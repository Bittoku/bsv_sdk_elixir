defmodule BSV.Tokens.Script.ReaderPushDataTest do
  @moduledoc """
  Tests for the `read_push_data/1` private function in `BSV.Tokens.Script.Reader`,
  exercised indirectly through `read_locking_script/1` on synthetic STAS3 scripts.

  Each test constructs a valid-enough STAS3 locking script with a specific opcode
  in the 2nd variable field (action data position at byte 21), then asserts that
  the parser correctly extracts the action_data_raw value for that opcode variant.

  Covers every pushdata opcode recognised by the STAS 3.0 specification:
  OP_0, bare push 1-75, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
  OP_1NEGATE, OP_1 through OP_16.
  """

  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.Reader

  # ---------------------------------------------------------------------------
  # The STAS3 base template hex (copied from Stas3Builder).
  # The template is 2812 bytes; its first 4 bytes are the STAS3 base prefix
  # (0x6D 0x82 0x73 0x63) and its last byte is OP_RETURN (0x6A).
  # ---------------------------------------------------------------------------
  @stas3_base_template_hex "6d82736301218763007b7b517c6e5667766b517f786b517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68766c936c7c5493686751687652937a76aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e011f7f7d7e01007e8111414136d08c5ed2bf3ba048afe6dcaebafe01005f80837e01007e7652967b537a7601ff877c0100879b7d648b6752799368537a7d9776547aa06394677768263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01417e7c6421038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b92186721023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc4868ad547f7701207f01207f7701247f517f7801007e02fd00a063546752687f7801007e817f727e7b517f7c01147d887f517f7c01007e817601619f6976014ea063517c7b6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f007b7b687602fd0a7f7701147f7c5579876b826475020100686b587a5893766b7a765155a569005379736382013ca07c517f7c51877b9a6352795487637101007c7e717101207f01147f75777c7567756c766b8b8b79518868677568686c6c7c6b517f7c817f788273638c7f776775010068518463517f7c01147d887f547952876372777c717c767663517f756852875779766352790152879a689b63517f77567a7567527c7681014f0161a5587a9a63015094687e68746c766b5c9388748c76795879888c8c7978886777717c767663517f7568528778015287587a9a9b745394768b797663517f756852877c6c766b5c936ea0637c8c768b797663517f75685287726b9b7c6c686ea0637c5394768b797663517f75685287726b9b7c6c686ea063755494797663517f756852879b676d689b63006968687c717167567a75686d7c518763755279686c755879a9886b6b6b6b6b6b6b827763af686c6c6c6c6c6c6c547a577a7664577a577a587a597a786354807e7e676d68aa880067765158a569765187645294587a53795a7a7e7e78637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6867587a6876aa5a7a7d54807e597a5b7a5c7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa5a7a7d877663516752687c72879b69537a6491687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e817602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75517f7c01147d887f517f7c01007e817601619f6976014ea0637c6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f68557964577988756d67716881687863567a677b68587f7c8153796353795287637b6b537a6b717c6b6b537a6b676b577a6b597a6b587a6b577a6b7c68677b93687c547f7701207f75748c7a7669765880044676a914780114748c7a76727b748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685c795c79636c766b7363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e0a888201218763ac67517f07517f73637c7f6876767e767e7e02ae687e7e7c557a00740111a063005a79646b7c748c7a76697d937b7b58807e6c91677c748c7a7d58807e6c6c6c557a680114748c7a748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685479635f79676c766b0115797363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7c637e677c6b7c6b7c6b7e7c6b68685979636c6c766b786b7363517f7c51876301347f77547f547f75786352797b01007e81957c01007e81965379a169676d68677568685c797363517f7c51876301347f77547f547f75786354797b01007e81957c01007e819678a169676d68677568687568740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68597a636c6c6c6d6c6c6d6c9d687c587a9d7d7e5c79635d795880041976a9145e797e0288ac7e7e6700687d7e5c7a766302006a7c7e827602fc00a06301fd7c7e536751687f757c7e0058807c7e687d7eaa6b7e7e7e7e7e7eaa78877c6c877c6c9a9b726d726d77776a"

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  @doc """
  Build a synthetic STAS3 locking-script binary with a custom action-data section.

  Layout:
    0x14 | owner(20) | action_data_bytes | base_template(2812) | 0x14 | redemption(20) | flags_push

  The base template's last byte is OP_RETURN (0x6A), so the parser sees:
    2811 bytes of template body | 0x6A | OP_RETURN payload (redemption + flags)

  ## Parameters
  - `action_data_bytes` — raw opcode+data bytes for the action-data field
  - `opts` — keyword list with optional `:owner` and `:redemption` overrides (default: 20-byte fills)

  ## Returns
  A binary representing a parseable STAS3 locking script.
  """
  defp build_stas3_with_action_data(action_data_bytes, opts \\ []) do
    owner = Keyword.get(opts, :owner, :binary.copy(<<0xAA>>, 20))
    redemption = Keyword.get(opts, :redemption, :binary.copy(<<0xBB>>, 20))
    {:ok, base_template} = Base.decode16(@stas3_base_template_hex, case: :mixed)

    # Flags: 0x01 (freezable) encoded as bare push (1 byte)
    flags_push = <<0x01, 0x01>>

    <<0x14>> <> owner <> action_data_bytes <> base_template <> <<0x14>> <> redemption <> flags_push
  end

  # ---------------------------------------------------------------------------
  # Test cases — one per opcode variant in the STAS 3.0 spec
  # ---------------------------------------------------------------------------

  describe "read_push_data via read_locking_script — opcode extraction" do
    test "OP_0 (0x00) yields action_data_raw nil" do
      script = build_stas3_with_action_data(<<0x00>>)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == nil
    end

    test "bare push 1 byte (0x01) extracts single byte" do
      action_bytes = <<0x01, 0xAB>>
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == <<0xAB>>
    end

    test "bare push 20 bytes (0x14) extracts 20-byte binary" do
      payload = :binary.copy(<<0xDE>>, 20)
      action_bytes = <<0x14>> <> payload
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == payload
      assert byte_size(parsed.stas3.action_data_raw) == 20
    end

    test "bare push 75 bytes (0x4B) extracts 75-byte binary" do
      payload = :binary.copy(<<0xFE>>, 75)
      action_bytes = <<0x4B>> <> payload
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == payload
      assert byte_size(parsed.stas3.action_data_raw) == 75
    end

    test "OP_PUSHDATA1 (0x4C) with 3-byte payload" do
      payload = <<0xAA, 0xBB, 0xCC>>
      action_bytes = <<0x4C, 0x03>> <> payload
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == payload
    end

    test "OP_PUSHDATA2 (0x4D) with 3-byte payload (little-endian length)" do
      payload = <<0xAA, 0xBB, 0xCC>>
      # Length 3 in little-endian 16-bit: <<0x03, 0x00>>
      action_bytes = <<0x4D, 0x03, 0x00>> <> payload
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == payload
    end

    test "OP_PUSHDATA4 (0x4E) with 2-byte payload (little-endian length)" do
      payload = <<0xDD, 0xEE>>
      # Length 2 in little-endian 32-bit: <<0x02, 0x00, 0x00, 0x00>>
      action_bytes = <<0x4E, 0x02, 0x00, 0x00, 0x00>> <> payload
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == payload
    end

    test "OP_1NEGATE (0x4F) yields opcode byte as action_data_raw" do
      action_bytes = <<0x4F>>
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == <<0x4F>>
    end

    test "OP_1 (0x51) yields opcode byte as action_data_raw" do
      action_bytes = <<0x51>>
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == <<0x51>>
    end

    test "OP_2 (0x52) yields opcode byte and sets frozen flag" do
      action_bytes = <<0x52>>
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == <<0x52>>
      assert parsed.stas3.frozen == true
    end

    test "OP_3 (0x53) yields opcode byte, not frozen" do
      action_bytes = <<0x53>>
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == <<0x53>>
      assert parsed.stas3.frozen == false
    end

    test "OP_16 (0x60) yields opcode byte as action_data_raw" do
      action_bytes = <<0x60>>
      script = build_stas3_with_action_data(action_bytes)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == :binary.copy(<<0xAA>>, 20)
      assert parsed.stas3.action_data_raw == <<0x60>>
    end
  end

  describe "read_push_data — owner and redemption extraction alongside action data" do
    test "custom owner is correctly extracted with bare push action data" do
      owner = :binary.copy(<<0x11>>, 20)
      redemption = :binary.copy(<<0x22>>, 20)
      payload = <<0xFF>>
      action_bytes = <<0x01>> <> payload

      script = build_stas3_with_action_data(action_bytes, owner: owner, redemption: redemption)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == owner
      assert parsed.stas3.redemption == redemption
      assert parsed.stas3.action_data_raw == payload
    end

    test "custom owner is correctly extracted with OP_PUSHDATA1 action data" do
      owner = :binary.copy(<<0x33>>, 20)
      redemption = :binary.copy(<<0x44>>, 20)
      payload = :binary.copy(<<0x99>>, 100)
      action_bytes = <<0x4C, 100>> <> payload

      script = build_stas3_with_action_data(action_bytes, owner: owner, redemption: redemption)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.owner == owner
      assert parsed.stas3.redemption == redemption
      assert parsed.stas3.action_data_raw == payload
      assert byte_size(parsed.stas3.action_data_raw) == 100
    end
  end

  describe "read_push_data — frozen flag only set for OP_2" do
    test "OP_1 is not frozen" do
      script = build_stas3_with_action_data(<<0x51>>)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.frozen == false
    end

    test "OP_2 is frozen" do
      script = build_stas3_with_action_data(<<0x52>>)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.frozen == true
    end

    test "OP_3 is not frozen" do
      script = build_stas3_with_action_data(<<0x53>>)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.frozen == false
    end

    test "bare push data is not frozen" do
      script = build_stas3_with_action_data(<<0x02, 0x52, 0x52>>)
      parsed = Reader.read_locking_script(script)

      assert parsed.script_type == :stas3
      assert parsed.stas3.frozen == false
    end
  end
end
