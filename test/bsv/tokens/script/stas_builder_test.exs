defmodule BSV.Tokens.Script.StasBuilderTest do
  use ExUnit.Case, async: true

  alias BSV.Tokens.Script.{StasBuilder, Reader}
  alias BSV.Tokens.ScriptFlags

  test "build and read roundtrip splittable" do
    owner = :binary.copy(<<0xAA>>, 20)
    redemption = :binary.copy(<<0xBB>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, true)
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas
    assert parsed.stas.owner_hash == owner
    assert parsed.stas.redemption_hash == redemption
    assert parsed.stas.flags == <<0x00>>
  end

  test "build and read roundtrip non-splittable" do
    owner = :binary.copy(<<0xCC>>, 20)
    redemption = :binary.copy(<<0xDD>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, false)
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.script_type == :stas
    assert parsed.stas.flags == <<0x01>>
  end

  test "build preserves token_id" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, true)
    parsed = Reader.read_locking_script(BSV.Script.to_binary(script))

    assert parsed.stas.token_id.pkh == redemption
  end

  test "template is 1431 bytes base" do
    owner = :binary.copy(<<0x11>>, 20)
    redemption = :binary.copy(<<0x22>>, 20)

    {:ok, script} = StasBuilder.build_stas_locking_script(owner, redemption, true)
    # Template (1431) + flags (2 bytes: OP_DATA_1 + flag)
    assert byte_size(BSV.Script.to_binary(script)) == 1433
  end

  # ---- v3 builder tests ----

  describe "build_stas_v3_locking_script/3" do
    test "builds with default opts (no flags, no action data)" do
      owner = :binary.copy(<<0xAA>>, 20)
      redemption = :binary.copy(<<0xBB>>, 20)

      assert {:ok, script} = StasBuilder.build_stas_v3_locking_script(owner, redemption)
      bin = BSV.Script.to_binary(script)
      assert is_binary(bin)
      assert byte_size(bin) > 100
    end

    test "builds with freezable flag" do
      owner = :binary.copy(<<0xAA>>, 20)
      redemption = :binary.copy(<<0xBB>>, 20)
      freeze_auth = :binary.copy(<<0xCC>>, 20)

      flags = %ScriptFlags{freezable: true}

      assert {:ok, script} =
               StasBuilder.build_stas_v3_locking_script(owner, redemption,
                 flags: flags,
                 service_fields: [freeze_auth]
               )

      bin = BSV.Script.to_binary(script)
      assert is_binary(bin)
    end

    test "builds with both flags" do
      owner = :binary.copy(<<0xAA>>, 20)
      redemption = :binary.copy(<<0xBB>>, 20)
      freeze_auth = :binary.copy(<<0xCC>>, 20)
      confiscate_auth = :binary.copy(<<0xDD>>, 20)

      flags = %ScriptFlags{freezable: true, confiscatable: true}

      assert {:ok, script} =
               StasBuilder.build_stas_v3_locking_script(owner, redemption,
                 flags: flags,
                 service_fields: [freeze_auth, confiscate_auth]
               )

      bin = BSV.Script.to_binary(script)
      assert is_binary(bin)
    end

    test "builds with frozen state" do
      owner = :binary.copy(<<0xAA>>, 20)
      redemption = :binary.copy(<<0xBB>>, 20)
      freeze_auth = :binary.copy(<<0xCC>>, 20)

      flags = %ScriptFlags{freezable: true}

      assert {:ok, script} =
               StasBuilder.build_stas_v3_locking_script(owner, redemption,
                 frozen: true,
                 flags: flags,
                 service_fields: [freeze_auth]
               )

      bin = BSV.Script.to_binary(script)
      assert is_binary(bin)
    end

    test "builds with swap action data" do
      owner = :binary.copy(<<0xAA>>, 20)
      redemption = :binary.copy(<<0xBB>>, 20)

      swap_data =
        {:swap,
         %{
           requested_script_hash: :binary.copy(<<0x11>>, 32),
           requested_pkh: :binary.copy(<<0x22>>, 20),
           rate_numerator: 39142,
           rate_denominator: 100
         }}

      assert {:ok, script} =
               StasBuilder.build_stas_v3_locking_script(owner, redemption,
                 action_data: swap_data
               )

      bin = BSV.Script.to_binary(script)
      assert is_binary(bin)
    end
  end
end
