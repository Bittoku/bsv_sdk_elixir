defmodule BSV.Base58Test do
  use ExUnit.Case, async: true

  test "encode/decode roundtrip" do
    data = <<1>> <> :crypto.strong_rand_bytes(31)
    encoded = BSV.Base58.encode(data)
    assert {:ok, ^data} = BSV.Base58.decode(encoded)
  end

  test "encode empty" do
    assert BSV.Base58.encode(<<>>) == ""
    assert {:ok, <<>>} = BSV.Base58.decode("")
  end

  test "leading zeros preserved" do
    data = <<0, 0, 0, 1>>
    encoded = BSV.Base58.encode(data)
    assert String.starts_with?(encoded, "111")
    assert {:ok, ^data} = BSV.Base58.decode(encoded)
  end

  test "known vector - encode and decode" do
    encoded = BSV.Base58.encode("Hello World")
    decoded = BSV.Base58.decode!(encoded)
    assert decoded == "Hello World"
  end

  test "check_encode/check_decode roundtrip" do
    payload = :crypto.strong_rand_bytes(20)
    encoded = BSV.Base58.check_encode(payload, 0x00)
    assert {:ok, {0x00, ^payload}} = BSV.Base58.check_decode(encoded)
  end

  test "invalid base58 character" do
    assert {:error, _} = BSV.Base58.decode("0OIl")
  end

  test "decode! raises on invalid" do
    assert_raise ArgumentError, fn -> BSV.Base58.decode!("0OIl") end
  end

  test "check_decode! success" do
    payload = :crypto.strong_rand_bytes(20)
    encoded = BSV.Base58.check_encode(payload, 0x00)
    assert {0x00, ^payload} = BSV.Base58.check_decode!(encoded)
  end

  test "check_decode! raises on invalid" do
    assert_raise ArgumentError, fn -> BSV.Base58.check_decode!("1") end
  end

  test "check_decode too short" do
    assert {:error, "too short"} = BSV.Base58.check_decode("1")
  end

  test "decode all zeros" do
    data = <<0, 0, 0>>
    encoded = BSV.Base58.encode(data)
    assert {:ok, ^data} = BSV.Base58.decode(encoded)
  end

  test "invalid checksum" do
    encoded = BSV.Base58.check_encode("test", 0x00)
    # Corrupt by changing a middle character
    chars = String.graphemes(encoded)
    mid = div(length(chars), 2)
    original_char = Enum.at(chars, mid)
    new_char = if original_char == "1", do: "2", else: "1"
    corrupted = List.replace_at(chars, mid, new_char) |> Enum.join()
    assert {:error, "invalid checksum"} = BSV.Base58.check_decode(corrupted)
  end
end
