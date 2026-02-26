defmodule BSV.MixProject do
  use Mix.Project

  def project do
    [
      app: :bsv_sdk,
      version: "1.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Feature-complete Bitcoin SV SDK for Elixir — primitives, scripts, transactions, wallet, tokens (STAS/DSTAS), SPV, and transport clients.",
      package: package(),
      docs: docs(),
      source_url: "https://github.com/Bittoku/bsv_sdk_elixir",
      homepage_url: "https://github.com/Bittoku/bsv_sdk_elixir",
      dialyzer: [plt_add_apps: [:jason, :req]]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp package do
    [
      name: "bsv_sdk",
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/Bittoku/bsv_sdk_elixir"
      },
      maintainers: ["Jerry David Chan"],
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "BSV",
      extras: ["README.md"],
      groups_for_modules: [
        "Primitives": [BSV.Crypto, BSV.PrivateKey, BSV.PublicKey, BSV.Base58, BSV.ChainHash, BSV.VarInt, BSV.SymmetricKey],
        "Script": [BSV.Script, BSV.Script.Address, BSV.Script.Opcodes, BSV.Script.Interpreter, BSV.Script.ScriptNum],
        "Transaction": [BSV.Transaction, BSV.Transaction.Builder, BSV.Transaction.Input, BSV.Transaction.Output, BSV.Transaction.P2PKH, BSV.Transaction.Sighash, BSV.Transaction.Template],
        "Wallet": [BSV.Wallet, BSV.Wallet.KeyDeriver, BSV.Wallet.ProtoWallet],
        "Message": [BSV.Message.Encrypted, BSV.Message.Signed],
        "Auth": [BSV.Auth.Certificate, BSV.Auth.MasterCertificate, BSV.Auth.VerifiableCertificate, BSV.Auth.Nonce],
        "SPV": [BSV.SPV.MerklePath, BSV.SPV.Beef, BSV.SPV.MerkleTreeParent],
        "Tokens": [BSV.Tokens, BSV.Tokens.Scheme, BSV.Tokens.TokenId, BSV.Tokens.Script.Reader, BSV.Tokens.Script.StasBuilder, BSV.Tokens.Script.StasBtgBuilder, BSV.Tokens.Script.DstasBuilder, BSV.Tokens.Factory.Contract, BSV.Tokens.Factory.Stas, BSV.Tokens.Factory.StasBtg, BSV.Tokens.Factory.Dstas, BSV.Tokens.Lineage, BSV.Tokens.Proof],
        "Transports": [BSV.ARC.Client, BSV.ARC.Config, BSV.JungleBus.Client, BSV.JungleBus.Config]
      ]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:req, "~> 0.5"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.0", only: [:dev, :test]},
      {:bypass, "~> 2.1", only: :test}
    ]
  end
end
