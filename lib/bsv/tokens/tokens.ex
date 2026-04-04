defmodule BSV.Tokens do
  @moduledoc """
  STAS and STAS 3.0 token support for BSV.

  This module provides the public API for token operations including:
  - Script classification and parsing
  - STAS token issuance, transfer, split, merge, and redemption
  - STAS 3.0 token issuance, spend, freeze/unfreeze, and swap

  ## Modules

  - `BSV.Tokens.TokenId` — Token identifier
  - `BSV.Tokens.Scheme` — Token scheme definition
  - `BSV.Tokens.ScriptType` — Script type classification
  - `BSV.Tokens.Script.Reader` — Script parsing
  - `BSV.Tokens.Script.StasBuilder` — STAS script builder
  - `BSV.Tokens.Script.Stas3Builder` — STAS 3 script builder
  - `BSV.Tokens.Factory.Contract` — Contract transaction builder
  - `BSV.Tokens.Factory.Stas` — STAS transaction factories
  - `BSV.Tokens.Factory.Stas3` — STAS 3 transaction factories
  """

  defdelegate read_locking_script(script), to: BSV.Tokens.Script.Reader
  defdelegate is_stas(script), to: BSV.Tokens.Script.Reader

  # BTG factory delegations
  defdelegate build_btg_transfer_tx(config), to: BSV.Tokens.Factory.StasBtg
  defdelegate build_btg_split_tx(config), to: BSV.Tokens.Factory.StasBtg
  defdelegate build_btg_merge_tx(config), to: BSV.Tokens.Factory.StasBtg
  defdelegate build_btg_checkpoint_tx(config), to: BSV.Tokens.Factory.StasBtg
end
