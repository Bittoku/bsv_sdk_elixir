defmodule BSV.Wallet.TypesTest do
  use ExUnit.Case, async: true

  alias BSV.Wallet.Types

  test "security level constants" do
    assert Types.security_level_silent() == 0
    assert Types.security_level_every_app() == 1
    assert Types.security_level_every_app_and_counterparty() == 2
  end

  test "Protocol struct" do
    p = %Types.Protocol{security_level: 1, protocol: "test"}
    assert p.security_level == 1
    assert p.protocol == "test"
  end

  test "Counterparty struct defaults" do
    c = %Types.Counterparty{}
    assert c.type == :uninitialized
    assert c.public_key == nil
  end

  test "Counterparty struct with values" do
    c = %Types.Counterparty{type: :anyone, public_key: nil}
    assert c.type == :anyone
  end

  test "EncryptionArgs struct" do
    proto = %Types.Protocol{security_level: 0, protocol: "test"}
    cp = %Types.Counterparty{type: :self}

    args = %Types.EncryptionArgs{
      protocol_id: proto,
      key_id: "key1",
      counterparty: cp
    }

    assert args.protocol_id == proto
    assert args.key_id == "key1"
    assert args.privileged == false
    assert args.privileged_reason == ""
    assert args.seek_permission == false
  end
end
