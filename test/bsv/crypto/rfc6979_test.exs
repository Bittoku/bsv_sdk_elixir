defmodule BSV.Crypto.RFC6979Test do
  use ExUnit.Case, async: true

  alias BSV.Crypto.RFC6979

  @vectors [
    %{
      d: "0000000000000000000000000000000000000000000000000000000000000001",
      message: "Everything should be made as simple as possible, but not simpler.",
      expected_k: "ec633bd56a5774a0940cb97e27a9e4e51dc94af737596a0c5cbb3d30332d92a5"
    },
    %{
      d: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      message: "Equations are more important to me, because politics is for the present, but an equation is something for eternity.",
      expected_k: "9dc74cbfd383980fb4ae5d2680acddac9dac956dca65a28c80ac9c847c2374e4"
    },
    %{
      d: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      message: "Not only is the Universe stranger than we think, it is stranger than we can think.",
      expected_k: "fd27071f01648ebbdd3e1cfbae48facc9fa97edc43bbbc9a7fdc28eae13296f5"
    },
    %{
      d: "0000000000000000000000000000000000000000000000000000000000000001",
      message: "How wonderful that we have met with a paradox. Now we have some hope of making progress.",
      expected_k: "f0cd2ba5fc7c183de589f6416220a36775a146740798756d8d949f7166dcc87f"
    },
    %{
      d: "69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64",
      message: "Computer science is no more about computers than astronomy is about telescopes.",
      expected_k: "6bb4a594ad57c1aa22dbe991a9d8501daf4688bf50a4892ef21bd7c711afda97"
    },
    %{
      d: "00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637",
      message: "...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not learning anywhere near enough",
      expected_k: "097b5c8ee22c3ea78a4d3635e0ff6fe85a1eb92ce317ded90b9e71aab2b861cb"
    },
    %{
      d: "000000000000000000000000000000000000000000056916d0f9b31dc9b637f3",
      message: "The question of whether computers can think is like the question of whether submarines can swim.",
      expected_k: "19355c36c8cbcdfb2382e23b194b79f8c97bf650040fc7728dfbf6b39a97c25b"
    }
  ]

  for {vector, idx} <- Enum.with_index(@vectors, 1) do
    @vector vector
    test "RFC 6979 k-generation vector #{idx}" do
      d = Base.decode16!(@vector.d, case: :lower)
      hash = :crypto.hash(:sha256, @vector.message)
      expected_k = Base.decode16!(@vector.expected_k, case: :lower)

      k = RFC6979.generate_k(d, hash)
      assert k == expected_k,
        "Vector #{unquote(idx)}: expected k=#{@vector.expected_k}, got #{Base.encode16(k, case: :lower)}"
    end
  end
end
