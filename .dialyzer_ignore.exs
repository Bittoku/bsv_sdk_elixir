# Pre-existing Dialyzer debt — unrelated to the STAS 3.0 v0.2.4 §15 work.
#
# Every entry below is debt that predates this MR's §15 port: it is either
# already present on the target `main` (the STAS v2 / STAS 3.0 template unlock
# paths, BIP contract helpers, BIP32 key derivation, bare-multisig) or from the
# May-2026 STAS 3.0 canonical-engine / swap-witness commits (6fa5e15, 12fd204),
# months before the §15 additions here. The §15 augment-directive Dialyzer
# errors the reviewer flagged (factory/stas3.ex augment paths) were FIXED by
# adding the `{:augment, binary()}` variant to `BSV.Tokens.ActionData.t()` — they
# are NOT suppressed here.
#
# Scoped by {file, warning_type}. `list_unused_filters: true` keeps this honest:
# if a file stops producing its listed warning, the build fails so the stale
# entry is removed rather than silently masking a future regression.
[
  # BIP contract helpers — unknown remote type (pre-existing, on main).
  {"lib/bsv/contract/helpers.ex", :unknown_type},
  # BIP32 extended-key derivation (pre-existing, on main).
  {"lib/bsv/ext_key.ex", :pattern_match},
  # STAS 3.0 swap-witness / minimal-LE helpers (commit 6fa5e15, 2026-05-21).
  {"lib/bsv/tokens/factory/stas3.ex", :pattern_match},
  # STAS 3.0 piece-array encoder (commit 12fd204, 2026-05-21).
  {"lib/bsv/tokens/script/stas3_pieces.ex", :pattern_match_cov},
  # STAS v2 unlock template (pre-existing, on main).
  {"lib/bsv/tokens/template/stas.ex", :pattern_match},
  # STAS 3.0 unlock template (pre-existing, on main).
  {"lib/bsv/tokens/template/stas3.ex", :pattern_match},
  # Bare-multisig (P2MPKH) unlock (pre-existing, on main).
  {"lib/bsv/transaction/p2mpkh.ex", :pattern_match}
]
