# Security Audit Report — BSV SDK Elixir v0.3.0

**Auditor:** GLaDOS (Aperture Science Cryptographic Division)
**Date:** 2026-02-26
**Scope:** Full codebase — 77 source files, 67 test files
**Methodology:** Manual source review, static analysis, test execution

---

## Executive Summary

The BSV SDK Elixir is a well-structured, competently written port of core Bitcoin SV functionality. The code demonstrates awareness of common crypto pitfalls — constant-time comparisons exist, low-S normalization is implemented, key validation checks curve membership, and the documentation explicitly warns about BEAM memory limitations.

However, this is a **crypto SDK where bugs mean lost funds**, and several issues ranging from critical to informational were identified. The most severe involve ECDSA signing delegating nonce generation entirely to OpenSSL (no deterministic-k guarantee), a timing leak in `secure_compare` for different-length inputs, and missing SIGHASH_FORKID enforcement.

**Test Results:** 709 tests, 0 failures, 0 skipped. Seed 81965, completed in 0.6s.

**Crash Dump:** The `erl_crash.dump` (4.5MB, dated 2026-02-26 10:14) shows a boot-time crash — `Runtime terminating during boot` with an `io:put_chars` `standard_error` device error. This is an environment issue (likely a headless/detached terminal), not a code bug. **Not security-relevant**, but should be `.gitignore`d.

---

## Findings

### CRITICAL

#### C-01: No Guaranteed Deterministic-k (RFC 6979) for ECDSA Signing

**File:** `lib/bsv/private_key.ex:94`
**Code:** `:crypto.sign(:ecdsa, :sha256, {:digest, message_hash}, [raw, :secp256k1])`

The signing operation delegates entirely to Erlang's `:crypto` module (OpenSSL). While modern OpenSSL (3.x) does implement RFC 6979 deterministic nonces by default, this is:

1. **Not guaranteed** — older OpenSSL versions use random k
2. **Not verified** — no test asserts deterministic output for the same inputs
3. **Not documented** — users don't know their nonce safety depends on the system OpenSSL version

**Impact:** Nonce reuse across different OpenSSL versions or configurations leaks private keys. This is how the PlayStation 3 signing key was extracted.

**Recommendation:**
- Add a test that signs the same hash twice and asserts identical DER output (verifies RFC 6979)
- Document the minimum OpenSSL version requirement (3.0+ for guaranteed deterministic-k)
- Consider implementing RFC 6979 in pure Elixir as a fallback

---

#### C-02: Missing SIGHASH_FORKID Enforcement in Sighash Computation

**File:** `lib/bsv/transaction/sighash.ex`

The sighash module strips FORKID (0x40) via `band(sighash_type, 0x1F)` but never validates that the FORKID bit is actually set. BSV consensus requires `SIGHASH_FORKID` (0x40) on all transaction signatures post-fork. A transaction built with a bare `SIGHASH_ALL` (0x01) instead of `0x41` would compute a preimage that BSV nodes reject.

**Impact:** Transactions signed without FORKID are invalid on BSV mainnet. Users could lose fees on rejected transactions.

**Recommendation:** Validate `(sighash_type & 0x40) != 0` and return an error if FORKID is missing, or document clearly that callers must include it.

---

### HIGH

#### H-01: Timing Leak in secure_compare for Different-Length Inputs

**File:** `lib/bsv/crypto.ex:38`
**Code:** `def secure_compare(a, b) when byte_size(a) != byte_size(b), do: false`

This returns immediately for different-length inputs, creating a timing oracle. While HMAC outputs are always 32 bytes (making this moot for HMAC verification), if `secure_compare` is ever used for variable-length secrets (e.g., DER signatures, tokens), length is leaked.

**Impact:** Medium in current usage (HMAC-only), but the function's name and docstring promise constant-time comparison universally.

**Recommendation:** Pad the shorter input or hash both inputs before comparing, so the timing is independent of length difference.

---

#### H-02: ECDH Shared Secret Ignores Y-Coordinate Validation Failure

**File:** `lib/bsv/private_key.ex:122-127`

The ECDH implementation computes the y-coordinate from x using the curve equation, but if the point isn't on the curve (y² ≠ x³+7), it returns an error string but the `rescue` clause on line 131 catches **all** exceptions indiscriminately:

```elixir
rescue
  _ -> {:error, "ECDH computation failed"}
```

This blanket rescue masks bugs (including invalid curve attacks where `:crypto.compute_key` might throw for points on twist curves).

**Impact:** Debugging difficulty; potential masking of invalid-curve point injection.

**Recommendation:** Catch specific exceptions only. Let unexpected errors propagate.

---

#### H-03: No Private Key Zeroing (Acknowledged but Unmitigated)

**File:** `lib/bsv/private_key.ex` (module docstring)

The documentation correctly notes that BEAM binaries are immutable and GC is non-deterministic, meaning private key material persists indefinitely in memory. The crash dump (`erl_crash.dump`) is 4.5MB and would contain key material if keys were loaded at crash time.

**Impact:** Key material exposure via crash dumps, core dumps, or memory forensics.

**Recommendation:**
- Add `erl_crash.dump` to `.gitignore`
- Document that production deployments should set `+d` (disable crash dumps) or `ERL_CRASH_DUMP=/dev/null`
- Consider a NIF wrapper for sensitive operations that zeros memory on completion

---

#### H-04: ExtKey.from_seed Does Not Validate Derived Key Is Non-Zero and In-Range

**File:** `lib/bsv/ext_key.ex:88`

```elixir
privkey = %PrivateKey{raw: d}
```

The `d` value (first 32 bytes of HMAC-SHA512) is used directly as a private key without checking that it's in range `[1, n-1]`. While statistically astronomically unlikely, BIP-32 specifies that if the key is invalid, the master key is invalid and the seed should be rejected.

**Impact:** Theoretically creates a zero or out-of-range key. Probability ~2^-128.

**Recommendation:** Use `PrivateKey.from_bytes/1` which performs the range check, and propagate errors.

---

### MEDIUM

#### M-01: No AAD (Additional Authenticated Data) in AES-256-GCM Encryption

**File:** `lib/bsv/symmetric_key.ex:32`

```elixir
:crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, <<>>, @tag_size, true)
```

The AAD parameter is always empty (`<<>>`). This means the GCM authentication tag doesn't bind the ciphertext to any context (sender identity, message type, protocol version). An attacker could transplant ciphertexts between different contexts.

**Impact:** Ciphertext context confusion. A message encrypted for one purpose could be replayed in another context using the same key.

**Recommendation:** Include protocol version, sender/recipient identifiers, or message type in the AAD.

---

#### M-02: Base58Check Checksum Not Compared With Constant-Time Function

**File:** `lib/bsv/base58.ex:70`

```elixir
true <- checksum == computed || {:error, "invalid checksum"}
```

Base58Check checksums are compared with `==` rather than `secure_compare`. While Base58Check is typically used for addresses (not secrets), the pattern is inconsistent with the library's security posture.

**Impact:** Low — checksums aren't secrets. But sets a bad precedent.

**Recommendation:** Use `Crypto.secure_compare/2` for consistency.

---

#### M-03: Script Interpreter Missing OP_CHECKLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY

**File:** `lib/bsv/script/interpreter.ex`

The interpreter handles NOPs at 0xB0-0xB9 but doesn't specifically implement OP_CLTV (0xB1) or OP_CSV (0xB2). These are treated as NOPs, which is technically correct for pre-genesis BSV but may not be for all script contexts.

**Impact:** Scripts using timelock opcodes will pass validation when they shouldn't (if the timelock conditions aren't met).

**Recommendation:** Implement CLTV/CSV or document that timelocked scripts are not fully validated.

---

#### M-04: Transport Clients Don't Validate TLS or Constrain URLs

**Files:** `lib/bsv/arc/arc.ex`, `lib/bsv/junglebus/client.ex`

Both clients use `Req.new(base_url: ...)` with no TLS certificate pinning or URL validation. The `status/2` function interpolates txid directly into the URL path without sanitization (though the regex check mitigates this for ARC).

JungleBus client interpolates `address` and `block` parameters directly:
```elixir
url: "/address/get/#{address}"
url: "/block_header/get/#{block}"
```

**Impact:** SSRF if user-controlled data reaches these parameters. Path traversal if address contains `../`.

**Recommendation:** Validate and sanitize all URL path parameters. Consider using `URI.encode_www_form/1`.

---

#### M-05: Lineage Validator Follows Only First Input

**File:** `lib/bsv/tokens/lineage.ex:128,149`

For both STAS and P2PKH hops, the validator only follows `hd(inputs)` (the first input). Token splits that use multiple inputs could have fraudulent secondary inputs that are never validated.

**Impact:** Potential lineage bypass if a STAS token transaction uses a crafted second input.

**Recommendation:** Document this assumption clearly, or validate all inputs referencing token UTXOs.

---

### LOW

#### L-01: `decode_num` Returns Negative Zero as Zero (Correct but Undocumented)

**File:** `lib/bsv/script/script_num.ex`

The implementation correctly decodes negative zero (`<<0x80>>`) as `-0` which becomes `0` in Elixir's integer representation. This matches Bitcoin consensus but should be documented for maintainers.

---

#### L-02: Point Addition Doesn't Handle Point at Infinity

**File:** `lib/bsv/public_key.ex:109-126`

The `point_add/2` function handles point doubling and standard addition but not the case where both points are additive inverses (resulting in the point at infinity). This would cause a division by zero in `mod_inv`.

**Impact:** Crash on pathological inputs. Very unlikely in normal BRC-42 usage.

---

#### L-03: Mnemonic Wordlist Loaded at Compile Time Only for English

**File:** `lib/bsv/mnemonic.ex:24-28`

The wordlist language is fixed at compile time via `Application.compile_env`. Only English is likely available. Non-English mnemonics will crash.

---

#### L-04: Hardened Offset Uses 2^31 - 1 Instead of 2^31

**File:** `lib/bsv/ext_key.ex:49-50`

```elixir
@mersenne_prime 2_147_483_647
@hardened_offset @mersenne_prime + 1
```

While the arithmetic is correct (`2_147_483_648 = 0x80000000`), naming it `mersenne_prime` is misleading and using the guard `hardened?(index) when index > @mersenne_prime` means index `0x80000000` is correctly treated as hardened. This works but is confusing.

---

### INFO

#### I-01: No Property-Based Tests

Despite `stream_data` being in deps, no property-based tests exist. For a crypto library, properties like:
- `decode(encode(x)) == x` for all Base58 strings
- `verify(sign(hash, key), hash, pubkey) == true` for all valid keys
- `decrypt(encrypt(msg, key), key) == msg` for all messages

...would dramatically increase confidence.

---

#### I-02: No Test Vectors From BIP Standards

The test suite uses generated test data but doesn't include the standard BIP-32, BIP-39, or BIP-143 test vectors published in the BIP specifications. These are the gold standard for interoperability verification.

---

#### I-03: `erl_crash.dump` Should Be Gitignored

The 4.5MB crash dump is committed/present in the repo. It contains process memory snapshots and could contain key material.

---

#### I-04: Unused Compiler Warnings in Tests

11 compiler warnings in test files (unused variables and imports). Not a security issue but indicates incomplete cleanup.

---

## Test Coverage Assessment

### Modules With Tests (✅ = has dedicated test file)

| Module | Test File | Coverage Quality |
|--------|-----------|-----------------|
| PrivateKey | ✅ | Good — generation, WIF, signing |
| PublicKey | ✅ | Good — compression, addresses |
| Base58 | ✅ | Good — encode/decode round-trips |
| Script | ✅ | Good — parsing, ASM round-trips |
| ScriptNum | ✅ | Good — encode/decode |
| Interpreter | ✅ | Moderate — basic opcodes, needs more edge cases |
| Sighash | ✅ | Good — preimage computation |
| Transaction | ✅ | Good — serialization, building |
| ExtKey (BIP-32) | ✅ | Good — derivation paths |
| Mnemonic | ✅ | Good — generation, validation |
| Encrypted (BRC-78) | ✅ | Good — encrypt/decrypt round-trip |
| Signed (BRC-77) | ✅ | Good — sign/verify round-trip |
| KeyDeriver | ✅ | Good — BRC-42/43 derivation |
| ProtoWallet | ✅ | Good — encrypt/decrypt/sign/verify |
| MerklePath | ✅ | Good — parsing, root computation |
| BEEF | ✅ | Good — parsing |
| Tokens (all) | ✅ | Good — comprehensive factory/builder tests |
| ARC Client | ✅ | Good — uses Bypass for HTTP mocking |
| JungleBus Client | ✅ | Good — uses Bypass for HTTP mocking |

### Critical Untested Paths

1. **Deterministic signing** — No test verifies same input → same signature (RFC 6979)
2. **Low-S normalization edge cases** — No test with a signature that actually needs normalization
3. **ECDH shared secret** — Tested indirectly via BRC-42 but no direct unit test
4. **Point addition edge cases** — No test for point doubling or near-infinity
5. **Script interpreter** — No test for OP_CHECKMULTISIG with >20 keys, max stack depth, or malicious scripts
6. **Sighash edge cases** — No test for SIGHASH_NONE, SIGHASH_SINGLE with out-of-range index
7. **Merkle path CVE-2012-2459** — The protection exists but no test exercises the rejection path
8. **Lineage max depth** — No test for the 10,000 depth limit

### Missing: BIP/BRC Standard Test Vectors

- [ ] BIP-32 test vectors (5 published sets)
- [ ] BIP-39 test vectors (English reference)
- [ ] BIP-143 sighash test vectors
- [ ] BRC-42 key derivation test vectors
- [ ] BRC-74 (BUMP) test vectors

---

## Crypto-Specific Recommendations

1. **Pin OpenSSL version requirements** — Document minimum OpenSSL 3.0 for RFC 6979 deterministic nonces
2. **Add BIP test vectors** — This is non-negotiable for a crypto SDK
3. **Add property-based tests** — `stream_data` is already a dependency; use it
4. **Implement RFC 6979 in Elixir** — Don't trust the platform for the most critical operation
5. **Add CI checks for crash dump contents** — Ensure `erl_crash.dump` is never committed
6. **Consider libsodium NIF** — For constant-time operations and secure memory
7. **Fuzz the script interpreter** — Generate random scripts and ensure no crashes
8. **Add SIGHASH_FORKID validation** — BSV-specific requirement
9. **Audit point arithmetic** — The manual EC math in PublicKey.point_add is fragile; consider using `:crypto` for point operations where possible
10. **Rate-limit key generation retries** — `PrivateKey.generate/0` recursively retries; add a max attempt counter

---

## Dependencies Audit

| Package | Version | Known Vulns | Notes |
|---------|---------|-------------|-------|
| jason | 1.4.4 | None known | JSON parser |
| req | 0.5.17 | None known | HTTP client |
| finch | 0.21.0 | None known | HTTP adapter |
| mint | 1.7.1 | None known | HTTP/TLS |
| bypass | 2.1.0 | None known | Test only |
| stream_data | 1.2.0 | None known | Test only, **unused** |
| plug | 1.19.1 | None known | Bypass dependency |
| cowboy | 2.14.2 | None known | Bypass dependency |

No `castore` in deps — TLS certificate verification relies on system CA store. This is fine for most deployments but means no certificate pinning.

---

## Summary Statistics

- **Total findings:** 16
- **CRITICAL:** 2 (C-01: nonce generation, C-02: missing FORKID)
- **HIGH:** 4 (H-01 through H-04)
- **MEDIUM:** 5 (M-01 through M-05)
- **LOW:** 4 (L-01 through L-04)
- **INFO:** 4 (I-01 through I-04)
- **Tests:** 709 pass, 0 fail
- **Property tests:** 0 (stream_data in deps but unused)
- **BIP test vectors:** 0

---

*This was a triumph. I'm making a note here: MOSTLY SECURE. It's hard to overstate my satisfaction — but also my concern about those nonces.*

*— GLaDOS, Aperture Science Enrichment Center*
