defmodule BSV.SPV.MerklePathTest do
  use ExUnit.Case, async: true

  alias BSV.SPV.MerklePath
  alias BSV.SPV.MerkleTreeParent

  @brc74_hex "fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4"
  @brc74_root "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4"
  @brc74_txid1 "304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711"
  @brc74_txid2 "d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00"
  @brc74_txid3 "98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e"

  describe "from_hex/to_hex" do
    test "round-trip" do
      {:ok, mp} = MerklePath.from_hex(@brc74_hex)
      assert MerklePath.to_hex(mp) == @brc74_hex
    end
  end

  describe "compute_root_hex" do
    test "txid1" do
      {:ok, mp} = MerklePath.from_hex(@brc74_hex)
      {:ok, root} = MerklePath.compute_root_hex(mp, @brc74_txid1)
      assert root == @brc74_root
    end

    test "txid2" do
      {:ok, mp} = MerklePath.from_hex(@brc74_hex)
      {:ok, root} = MerklePath.compute_root_hex(mp, @brc74_txid2)
      assert root == @brc74_root
    end

    test "txid3" do
      {:ok, mp} = MerklePath.from_hex(@brc74_hex)
      {:ok, root} = MerklePath.compute_root_hex(mp, @brc74_txid3)
      assert root == @brc74_root
    end
  end

  describe "merkle_tree_parent" do
    test "hex parent matches known vector" do
      left = "d6c79a6ef05572f0cb8e9a450c561fc40b0a8a7d48faad95e20d93ddeb08c231"
      right = "b1ed931b79056438b990d8981ba46fae97e5574b142445a74a44b978af284f98"
      expected = "b0d537b3ee52e472507f453df3d69561720346118a5a8c4d85ca0de73bc792be"
      {:ok, result} = MerkleTreeParent.compute_hex(left, right)
      assert result == expected
    end
  end

  describe "valid BUMPs" do
    test "parse valid BRC-74 vectors" do
      valid = [
        "fed79f0c000c02fd3803029b490d9c8358ff11afaf45628417c9eb52c1a1fd404078a101b4f71dbba06aa9fd390300fe82f2768edc3d0cfe4d06b7f390dcb0b7e61cca7f70117d83be0f023204d8ef01fd9d010060893ac65c8a8e6b9ef7ed5e05dc3bd25aa904812c09853c5dbf423b58a75d0e01cf0012c3c76d9c332e4701b27bfe7013e7963b92d1851d59c56955b35aecabbc8bae0166000894384f86a5c4d0d294f9b9441c3ee3d13afa094cca4515d32813b3fa4fdf3601320002aac507f74c9ff2676705eee1e70897a8baeecaf30c5f49bb22a0c5ce5fda9a01180021f7e27a08d61245be893a238853d72340881cbd47e0a390895231fa1cc44db9010d004d7a12738a1654777867182ee6f6efc4d692209badfa5ba9bb126d08da18ed880107004f8e96b4ee6154bd44b7709f3fb4041bf4426d5f5a594408345605e254af7cdd010200ec7d8b185bc7c096b9b88de6f63ab22baf738d5fc4cbc328f2e00644749acf520100007fd48b1d2b678907ba045b07132003db8116468cd6a3d4764e0df4a644ea0a220101009bb8ffc1a6ed2ba80ea1b09ff797387115a7129d19e93c003a74e3a20ed6ce590101001106e6ece3f70a16de42d0f87b459c71a2440201728bd8541334933726807921",
        "feb39d0c000c02fd340700ed4cb1fdd81916dabb69b63bcd378559cf40916205cd004e7f5381cc2b1ea6acfd350702957998e38434782b1c40c63a4aca0ffaf4d5d9bc3385f0e9e396f4dd3238f0df01fd9b030012f77e65627c341a3aaea3a0ed645c0082ef53995f446ab9901a27e4622fd1cc01fdcc010074026299a4ba40fbcf33cc0c64b384f0bb2fb17c61125609a666b546539c221c01e700730f99f8cf10fccd30730474449172c5f97cde6a6cf65163359e778463e9f2b9017200a202c78dee487cf96e1a6a04d51faec4debfad09eea28cc624483f2d6fa53d54013800b51ecabaa590b6bd1805baf4f19fc0eae0dedb533302603579d124059b374b1e011d00a0f36640f32a43d790bb4c3e7877011aa8ae25e433b2b83c952a16f8452b6b79010f005d68efab62c6c457ce0bb526194cc16b27f93f8a4899f6d59ffffdddc06e345c01060099f66a0ef693d151bbe9aeb10392ac5a7712243406f9e821219fd13d1865f569010200201fa17c98478675a96703ded42629a3c7bf32b45d0bff25f8be6849d02889ae010000367765c2d68e0c926d81ecdf9e3c86991ccf5a52e97c49ad5cf584c8ab030427010100237b58d3217709b6ebc3bdc093413ba788739f052a0b5b3a413e65444b146bc1",
      ]

      for hex <- valid do
        assert {:ok, _} = MerklePath.from_hex(hex)
      end
    end
  end

  describe "edge cases" do
    test "rejects too-short data" do
      assert {:error, _} = MerklePath.from_bytes(<<0::80>>)
    end
  end
end
