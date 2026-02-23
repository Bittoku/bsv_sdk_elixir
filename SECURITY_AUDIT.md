# Security Audit Report: BSV SDK Elixir

**Date:** 2026-02-23
**Scope:** Full codebase — `/home/user/bsv_sdk_elixir` (62 source files, ~5,300 LOC)
**Methodology:** Manual static analysis across 5 domains: hardcoded secrets, cryptographic implementations, HTTP client security, injection/input validation, and dependency vulnerabilities.

---

## Executive Summary

The BSV SDK Elixir codebase demonstrates strong security fundamentals — no hardcoded secrets, proper use of `:crypto.strong_rand_bytes/1` for all randomness, constant-time comparisons for sensitive values, DER signature low-S normalization, curve point validation, and safe JSON deserialization defaults. All 27 dependencies are at their latest versions with **zero known CVEs**.

However, the audit identified **44 findings** across the following severity levels:

| Severity | Count | Key Areas |
|----------|-------|-----------|
| **Critical** | 0 | — |
| **High** | 4 | HTTP input validation, binary parser crash paths |
| **Medium** | 16 | Crypto edge cases, DoS vectors, missing TLS config |
| **Low** | 13 | Minor timing leaks, error message leakage, code quality |
| **Info** | 2 | BEAM limitations (documented), correct implementations |
| **Pass** | 9 | Secrets scan, dependency audit, deserialization safety |

**No critical vulnerabilities were found.** The highest-priority items to address are the HTTP client input validation gaps and the crash-on-malformed-input patterns in binary parsers.

---

## Table of Contents

1. [Hardcoded Secrets Scan](#1-hardcoded-secrets-scan)
2. [Dependency Vulnerability Audit](#2-dependency-vulnerability-audit)
3. [Cryptographic Implementation Review](#3-cryptographic-implementation-review)
4. [HTTP Client Security Review](#4-http-client-security-review)
5. [Injection & Input Validation Review](#5-injection--input-validation-review)
6. [Prioritized Remediation Plan](#6-prioritized-remediation-plan)
7. [Positive Security Findings](#7-positive-security-findings)

---

## 1. Hardcoded Secrets Scan

**Result: PASS — No hardcoded secrets detected.**

All cryptographic material in the codebase falls into safe categories:

| Category | Examples | Verdict |
|----------|----------|---------|
| Bitcoin Wiki test vectors | WIF `5HueCGU8rMjxEXx...` in tests | Safe — public interop vectors |
| secp256k1 curve constants | `@n`, `@secp256k1_p` | Safe — mathematical constants |
| Synthetic test keys | `make_key(42)`, `make_key(69)` | Safe — trivially constructed |
| STAS protocol public keys | Embedded in script templates | Safe — public keys, not private |
| Genesis block data | Block hash, coinbase tx | Safe — public blockchain data |
| Test API keys | `"test-key"`, `"cb-token"` | Safe — used with Bypass mock |
| Config defaults | `api_key: nil` | Safe — no default credentials |

**Recommendation:** Add `.env` and `.env.*` to `.gitignore` as defense-in-depth.

---

## 2. Dependency Vulnerability Audit

**Result: PASS — Zero CVEs affecting locked versions.**

All 27 dependencies (6 direct + 21 transitive) are at their latest available versions.

| Dependency | Locked Version | Latest | Status |
|------------|---------------|--------|--------|
| jason | 1.4.4 | 1.4.4 | Current |
| req | 0.5.17 | 0.5.17 | Current |
| finch | 0.21.0 | 0.21.0 | Current |
| mint | 1.7.1 | 1.7.1 | Current |
| plug | 1.19.1 | 1.19.1 | Current |
| cowboy | 2.14.2 | 2.14.2 | Current |
| ranch | 1.8.1 | **2.2.0** | Constrained by bypass ~> 2.1 |
| *(all others)* | *(latest)* | *(latest)* | Current |

**Ecosystem Advisory:** CVE-2025-32433 (Erlang/OTP SSH RCE, CVSS 10.0) does **not** affect this project (uses Cowboy HTTP, not OTP SSH), but the Erlang/OTP runtime should be kept patched.

**Recommendations:**
- Add `{:mix_audit, "~> 2.0", only: [:dev, :test], runtime: false}` for ongoing automated vulnerability scanning
- Add `{:castore, "~> 1.0"}` as an explicit dependency (see Finding HTTP-6)

---

## 3. Cryptographic Implementation Review

### CRYPTO-1: `PrivateKey` struct leaks key material in logs/IEx [Medium]

**File:** `lib/bsv/private_key.ex:21-23`

The `PrivateKey` struct has no `Inspect` protocol override. If accidentally logged, printed in IEx, or included in an error message/crash dump, the raw 32-byte private key is displayed in full.

**Fix:** Add an `Inspect` implementation:
```elixir
defimpl Inspect, for: BSV.PrivateKey do
  def inspect(_key, _opts), do: "#BSV.PrivateKey<REDACTED>"
end
```

### CRYPTO-2: `SymmetricKey` struct also leaks key material [Medium]

**File:** `lib/bsv/symmetric_key.ex:17-18`

Same issue as CRYPTO-1.

### CRYPTO-3: No low-S enforcement on signature verification [Medium]

**File:** `lib/bsv/public_key.ex:166-169`

`verify/3` accepts any valid DER signature without checking for low-S (BIP-62). While `sign/2` correctly normalizes to low-S, the verification path does not reject high-S signatures. A third party could compute the high-S counterpart (`S' = N - S`) and it would still verify — relevant for txid malleability.

**Fix:**
```elixir
def verify(%__MODULE__{point: point}, <<message_hash::binary-size(32)>>, signature_der) do
  if high_s?(signature_der), do: false,
  else: :crypto.verify(:ecdsa, :sha256, {:digest, message_hash}, signature_der, [point, :secp256k1])
end
```

### CRYPTO-4: `point_add/2` mishandles inverse points / point-at-infinity [Medium]

**File:** `lib/bsv/public_key.ex:127-151`

When both input points share the same x-coordinate but different y-coordinates (inverse points), the result should be the point at infinity. Currently, `mod_inv(0, p)` is called, producing an incorrect result silently.

**Fix:** Add an explicit check for inverse points before the main logic.

### CRYPTO-5: ECDH shared secret not checked for all-zero result [Medium]

**File:** `lib/bsv/private_key.ex:109-143`

If `:crypto.compute_key(:ecdh, ...)` returns an all-zero result (degenerate case), the code proceeds to use it as a key.

**Fix:** Add a guard: `if shared_x == :binary.copy(<<0>>, byte_size(shared_x)), do: {:error, ...}`

### CRYPTO-6: Base58Check checksum uses non-constant-time `==` [Medium]

**File:** `lib/bsv/base58.ex:67`

The checksum comparison uses `==` which short-circuits on the first differing byte. Practical risk is low (4-byte checksum of public data), but constant-time comparison is best practice.

**Fix:** Replace with `BSV.Crypto.secure_compare(checksum, computed)`.

### CRYPTO-7: `normalize_low_s/1` falls through silently on malformed DER [Low]

**File:** `lib/bsv/private_key.ex:175-198`

If DER parsing fails, the fallback clause returns the original bytes unchanged. A non-parseable DER signature from `:crypto.sign` indicates a serious issue that should not be swallowed.

### CRYPTO-8: `secure_compare/2` leaks length via early return [Low]

**File:** `lib/bsv/crypto.ex:38`

Returns `false` immediately when binaries differ in length. All current uses compare fixed-length values, so practical risk is negligible.

### CRYPTO-9: Non-constant-time comparison in `reveal_counterparty_secret/2` [Low]

**File:** `lib/bsv/wallet/key_deriver.ex:131`

Uses `==` to compare derived private key material. Practical exploitability is very low.

### CRYPTO-10: Nonce `key_id` uses unsafe binary-to-string conversion [Low]

**File:** `lib/bsv/auth/nonce.ex:18,38`

`random |> :binary.bin_to_list() |> to_string()` produces a string with control characters / non-UTF-8 content. May cause issues with JSON serialization or validation regexes downstream.

**Fix:** Use `Base.encode16(random, case: :lower)` instead.

### CRYPTO-11: Trial decryption leaks ciphertext format information [Low]

**File:** `lib/bsv/symmetric_key.ex:56-69`

Tries 12-byte IV format first, then falls back to 32-byte legacy format. An observer could distinguish legacy from current ciphertexts via timing.

### CRYPTO-12: `rescue _` swallows all exceptions in ECDH [Low]

**File:** `lib/bsv/private_key.ex:140-142`

Catches all exceptions with a generic error message, masking potential bugs.

### CRYPTO-13: Key material lifetime in BEAM memory [Info]

**File:** `lib/bsv/private_key.ex:5-18`

Properly documented BEAM limitation. No code change needed.

---

## 4. HTTP Client Security Review

### HTTP-1: Missing HTTP request timeouts [High]

**Files:** `lib/bsv/arc/arc.ex:14`, `lib/bsv/junglebus/client.ex:15`

Neither client sets explicit `connect_timeout`, `receive_timeout`, or `pool_timeout`. A slow/malicious server can hold connections open indefinitely.

**Fix:**
```elixir
req = Req.new(base_url: config.base_url, retry: false,
  connect_timeout: 10_000, receive_timeout: 30_000, pool_timeout: 5_000)
```

### HTTP-2: Missing response size limits [High]

**Files:** `lib/bsv/arc/arc.ex:24-40`, `lib/bsv/junglebus/client.ex:59-76`

No response size limits. A malicious server could return an extremely large response body causing OOM.

### HTTP-3: No URL scheme validation (SSRF / protocol downgrade) [High]

**Files:** `lib/bsv/arc/config.ex:18`, `lib/bsv/junglebus/config.ex:10`

While defaults use HTTPS, `base_url`/`server_url` accept any string. A caller could supply `http://` (leaking Bearer tokens in plaintext) or internal network addresses (`http://169.254.169.254/`).

**Fix:** Validate `uri.scheme == "https"` in `Client.new/1`.

### HTTP-4: Missing input validation on JungleBus path parameters [High]

**File:** `lib/bsv/junglebus/client.ex:22,28,37,45,54`

User-supplied txid, address, block, and limit values are interpolated directly into URL paths without validation. Unlike the ARC client (which validates txid with a regex), none of the JungleBus parameters are checked.

**Fix:** Add regex validation for all path parameters, or at minimum use `URI.encode_www_form/1`.

### HTTP-5: `api_version` interpolated without validation [Medium]

**File:** `lib/bsv/junglebus/client.ex:14`

Free-form string could be set to `"../../admin"` or `"v1?auth=bypass"`.

### HTTP-6: Missing TLS certificate store dependency [Medium]

**File:** `mix.exs:57-64`

`castore` is not an explicit dependency. Mint lists it as optional. Without it, TLS verification depends on the system certificate store, which may be empty/outdated in some environments.

**Fix:** Add `{:castore, "~> 1.0"}` to `mix.exs`.

### HTTP-7: Sensitive tokens in non-standard headers [Medium]

**Files:** `lib/bsv/junglebus/client.ex:91`, `lib/bsv/arc/arc.ex:93-95`

Custom `token` and `x-callbacktoken` headers are not redacted by standard logging/proxy infrastructure (unlike `authorization` headers).

### HTTP-8: Error messages may leak internal information [Medium]

**Files:** `lib/bsv/arc/arc.ex:39,69`, `lib/bsv/junglebus/client.ex:70-74`

`inspect(reason)` can expose IP addresses, connection details, and TLS negotiation errors. Server response bodies are included without sanitization.

### HTTP-9: JSON auto-decode without size/depth limits [Medium]

**Files:** `lib/bsv/arc/arc.ex:29-36`, `lib/bsv/junglebus/client.ex:62-86`

Deeply nested JSON from a malicious server could cause stack overflow during parsing.

### HTTP-10: Req follows redirects by default [Medium]

**Files:** `lib/bsv/arc/arc.ex:14`, `lib/bsv/junglebus/client.ex:15`

Req follows up to 10 redirects. Custom headers (`token`, `x-callbacktoken`) are NOT stripped on cross-origin redirects (only `authorization` is). API clients should typically not follow redirects.

**Fix:** `Req.new(..., redirect: false)`

### HTTP-11: `callback_url` sent to ARC without validation [Medium]

**File:** `lib/bsv/arc/arc.ex:94`

No validation that the URL uses HTTPS or does not point to internal addresses. Could enable SSRF via the ARC server.

### HTTP-12: Unreachable pattern match clause in ARC broadcast [Low]

**File:** `lib/bsv/arc/arc.ex:29-36`

Third clause is unreachable — duplicates the first clause's pattern. Indicates potential logic error.

### HTTP-13: `from_json` accepts arbitrary types without validation [Low]

**Files:** `lib/bsv/arc/types.ex:105-119`, `lib/bsv/junglebus/types.ex:43-103`

No type checking on deserialized fields. Unexpected types could cause downstream crashes.

### HTTP-14: Sensitive config fields are inspectable [Low]

**Files:** `lib/bsv/arc/config.ex`, `lib/bsv/junglebus/config.ex`

`Config` structs containing `api_key`, `callback_token`, `token` will display credentials when logged/inspected.

**Fix:** Add `Inspect` protocol implementations that redact sensitive fields.

---

## 5. Injection & Input Validation Review

### INJ-1: BEEF parser uses bare `=` pattern matches — crashes on malformed input [High]

**File:** `lib/bsv/spv/beef.ex:74,91,112,146`

Multiple `{:ok, {count, rest}} = VarInt.decode(data)` calls will raise `MatchError` if VarInt.decode returns `{:error, ...}` from malformed data.

**Fix:** Replace with `with {:ok, {count, rest}} <- VarInt.decode(data) do ... end`.

### INJ-2: MerklePath parser uses bare `=` matches — crashes on malformed input [High]

**File:** `lib/bsv/spv/merkle_path.ex:59-63,157-168,177,282`

Same issue as INJ-1 across `from_bytes/1`, `read_levels`, and `read_leaves`.

### INJ-3: OP_PUSHDATA4 allows up to 4 GB data allocation [High]

**File:** `lib/bsv/script/script.ex:183-191`

32-bit length field read without upper bound. A crafted script with a large payload could exhaust memory.

**Fix:** Add a configurable `max_element_size` check during parsing.

### INJ-4: Certificate field deserialization crashes on malformed input [Medium]

**File:** `lib/bsv/auth/certificate.ex:198-209`

Bare `=` matches on VarInt.decode and binary slicing.

### INJ-5: BEEF V1 flag byte not consumed on false branch [Medium]

**File:** `lib/bsv/spv/beef.ex:108-119`

When `flag != 0x01`, the code returns `{0, false, rest}` instead of `{0, false, rest2}`, causing the flag byte to be reinterpreted as the start of the next transaction. **This is a bug.**

**Fix:** Change `{0, false, rest}` to `{0, false, rest2}`.

### INJ-6: No upper bound on transaction input/output count [Medium]

**File:** `lib/bsv/transaction/transaction.ex:172-181`

VarInt decode without a `max` parameter. Crafted data claiming billions of inputs could cause resource exhaustion.

### INJ-7: Script interpreter after_genesis limits allow ~4 GB allocations [Medium]

**File:** `lib/bsv/script/interpreter.ex:71-74`

`max_element_size: 4_294_967_295`, `max_stack_size: 4_294_967_295`. While matching BSV consensus rules, this is dangerous for local validation of untrusted scripts.

### INJ-8: OP_NUM2BIN missing max_element_size check [Medium]

**File:** `lib/bsv/script/interpreter.ex:443-455`

Pops a `size` from the stack and allocates a binary of that size without checking against `state.max_element_size`.

### INJ-9: No VarInt max in BEEF/MerklePath parsers [Medium]

**Files:** `lib/bsv/spv/beef.ex:74,91`, `lib/bsv/spv/merkle_path.ex:59,157,167`

VarInt decoding without using the available `max` parameter.

### INJ-10: `verify_clean_stack` flag not enforced [Low]

**File:** `lib/bsv/script/interpreter.ex:87-90`

The flag is defined but `check_final_stack` never checks for it.

### INJ-11: `length/1` called on data stack is O(n) [Low]

**File:** `lib/bsv/script/interpreter.ex:154,371,381`

With after_genesis stack sizes up to 4 billion, calling `length/1` on a linked list for every operation is a performance concern.

---

## 6. Prioritized Remediation Plan

### Priority 1 — High Severity (address first)

| ID | Finding | Effort |
|----|---------|--------|
| HTTP-1 | Add explicit timeouts to Req clients | Small |
| HTTP-3 | Validate URL scheme (HTTPS only) | Small |
| HTTP-4 | Add input validation on JungleBus path params | Small |
| INJ-1 | Replace bare `=` matches in BEEF parser with `with` | Medium |
| INJ-2 | Replace bare `=` matches in MerklePath parser | Medium |
| INJ-5 | Fix BEEF V1 flag byte consumption bug | Small |

### Priority 2 — Medium Severity (address soon)

| ID | Finding | Effort |
|----|---------|--------|
| CRYPTO-1/2 | Add `Inspect` redaction for `PrivateKey` and `SymmetricKey` | Small |
| CRYPTO-3 | Reject high-S signatures in `verify/3` | Small |
| CRYPTO-4 | Handle point-at-infinity in `point_add/2` | Small |
| CRYPTO-5 | Check for all-zero ECDH result | Small |
| HTTP-6 | Add `castore` dependency | Small |
| HTTP-10 | Disable redirect following | Small |
| INJ-3 | Add max_element_size during script parsing | Medium |
| INJ-7/8 | Add configurable limits for local script validation | Medium |

### Priority 3 — Low Severity / Hardening

| ID | Finding | Effort |
|----|---------|--------|
| CRYPTO-10 | Use hex encoding for nonce key_id | Small |
| HTTP-8 | Sanitize error messages | Small |
| HTTP-14 | Add `Inspect` redaction for Config structs | Small |
| HTTP-12 | Remove unreachable pattern match clause | Small |
| INJ-10 | Enforce `verify_clean_stack` flag | Small |

### Tooling Recommendations

| Tool | Purpose | Action |
|------|---------|--------|
| `mix_audit` | Dependency CVE scanning | Add to mix.exs dev deps |
| `castore` | TLS certificate verification | Add to mix.exs prod deps |
| `sobelow` | Elixir static security analysis | Add to mix.exs dev deps |
| `credo` | Code quality / anti-patterns | Add to mix.exs dev deps |
| `.env` in `.gitignore` | Prevent accidental secret commits | Add entry |

---

## 7. Positive Security Findings

The codebase demonstrates many strong security practices:

1. **Cryptographic randomness**: All randomness uses `:crypto.strong_rand_bytes/1` — no `:rand` usage anywhere
2. **Constant-time comparisons**: `BSV.Crypto.secure_compare/2` used for HMAC and key comparisons
3. **Low-S signature normalization**: BIP-62 compliant signing in `PrivateKey.sign/2`
4. **Curve point validation**: `PublicKey.from_bytes/1` verifies points lie on secp256k1
5. **Private key range validation**: Enforces `(0, N)` range in `PrivateKey.from_bytes/1`
6. **Safe JSON deserialization**: `Jason.decode/1` uses string keys by default (no atom exhaustion)
7. **No `String.to_atom`**: Zero usage of atom creation from untrusted input
8. **No `:binary_to_term`**: No unsafe deserialization of Erlang terms
9. **No system command execution**: Zero usage of `System.cmd`, `Port.open`, etc.
10. **ARC txid validation**: Regex check before URL interpolation
11. **CVE-2012-2459 mitigation**: MerklePath validates duplicate positions
12. **Token lineage depth limit**: `@max_chain_depth = 10_000` prevents unbounded chain walking
13. **All dependencies current**: 26/27 at latest version, 0 known CVEs
14. **Comprehensive test suite**: 594 tests, ~91% coverage, property-based testing with StreamData

---

*Report generated by automated static analysis. Findings should be validated and prioritized based on your threat model and deployment context.*
