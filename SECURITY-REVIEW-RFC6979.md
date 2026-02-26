# Security Review: RFC 6979 Deterministic ECDSA Signing

**Reviewer:** GLaDOS (automated cryptographic audit)
**Date:** 2026-02-26
**Scope:** Commits 05c70d1..4c87e7a — RFC 6979 k-generation, pure-Elixir ECDSA, integration
**Test results:** 737 tests, 0 failures (full suite)

---

## Summary

The implementation is **functionally correct** — 7 known-answer vectors pass, cross-validation against `:crypto.verify` succeeds, and determinism is confirmed. The RFC 6979 HMAC-DRBG loop, ECDSA math, and DER encoding are all sound for production use on secp256k1. Several observations below, rated by severity.

---

## Findings

### 🔴 HIGH — Timing Side-Channel in EC Point Multiplication

**File:** `lib/bsv/crypto/ecdsa.ex`, `ec_point_mul/2`

The double-and-add algorithm branches on each bit of `k`:
```elixir
if rem(k, 2) == 0, do: doubled, else: ec_point_add(doubled, point)
```

This is **not constant-time**. An attacker observing execution timing (cache timing, power analysis) can recover bits of `k`. Since `k` is deterministic per RFC 6979, recovering `k` from *any single signature* reveals the private key directly (`d = (s·k - z) · r⁻¹ mod n`).

**Practical risk:** LOW-MEDIUM. Exploiting this requires:
- Local process co-residency or physical access
- High-resolution timing measurements on BEAM VM (difficult due to GC jitter, scheduler preemption)
- The BEAM's bignum arithmetic already has variable timing

**Mitigation:** For high-value signing, use a NIF wrapping libsecp256k1 (which uses constant-time scalar multiplication). For typical application use, the BEAM's non-deterministic scheduling provides *incidental* but not *guaranteed* protection.

**Verdict:** Acceptable for application-layer signing. Document the limitation. Do NOT use for HSM-grade or hardware-adjacent signing.

---

### 🟡 MEDIUM — No Validation of r ≠ 0 and s ≠ 0 After Signing

**File:** `lib/bsv/crypto/ecdsa.ex`, `sign_with_k/3`

The code computes `r = rem(rx, @n)` and `s` but never checks `r == 0` or `s == 0`. Per the ECDSA spec, if either is zero the signature is invalid and a new `k` must be tried.

With RFC 6979 on secp256k1, `r = 0` requires `k·G` to have x-coordinate that is a multiple of `n` — this is astronomically unlikely (probability ≈ 2⁻¹²⁸). Similarly `s = 0` requires `z + r·d ≡ 0 (mod n)`, also negligible.

**Verdict:** Theoretically incomplete, practically irrelevant. Adding `if r == 0 or s == 0, do: raise "degenerate signature"` would be trivially correct but the condition is unreachable in practice.

---

### 🟡 MEDIUM — EC Point Addition: Missing Inverse-Point Check

**File:** `lib/bsv/crypto/ecdsa.ex`, `ec_point_add/2`

When `x1 == x2` and `y1 ≠ y2` (i.e., P + (-P) = ∞), the current code falls through to the general addition formula where `x2 - x1 = 0`, causing `mod_inverse(0, p)` which raises `"no inverse"`.

This cannot occur during normal signing (would require `k` such that an intermediate doubled point equals the negative of the generator, astronomically unlikely), but it's an edge case in the public API.

**Verdict:** Not exploitable in signing. Would crash if someone calls `ec_point_add` directly with inverse points. Add a guard:
```elixir
def ec_point_add({x1, y1}, {x2, y2}) when x1 == x2, do: :infinity
```

---

### 🟢 LOW — RFC 6979 bits2octets Simplification

**File:** `lib/bsv/crypto/rfc6979.ex`, `generate_k/2`

The implementation reduces `h1` by subtraction (`h1 - n`) if `h1 >= n`, rather than using proper modular reduction. This is correct because for SHA-256 output (256 bits) and secp256k1's `n` (also 256 bits), at most one subtraction is needed. The 7 test vectors confirm correctness.

**Verdict:** Correct. The simplification is valid for qlen == hlen == 256.

---

### 🟢 LOW — DER Encoding of Zero Values

**File:** `lib/bsv/crypto/ecdsa.ex`, `encode_der_integer/1`

`:binary.encode_unsigned(0)` returns `<<0>>`, which DER-encodes correctly as `02 01 00`. This is fine. However, this path is unreachable in practice (see r/s ≠ 0 finding above).

**Verdict:** Correct behavior, unreachable code path.

---

### 🟢 LOW — Large Integer Arithmetic in Modular Operations

**File:** `lib/bsv/crypto/ecdsa.ex`, `ec_point_add/2` and `ec_point_double/2`

The code uses `@p * 2` and `@p * 3` padding to avoid negative intermediate values in `rem/2`. This works because:
- `y2 - y1` can be at most `-(@p - 1)`, so adding `2·p` guarantees positive
- `lam² - x1 - x2` can be at most `-2·(@p - 1)`, so adding `3·p` guarantees positive

**Verdict:** Correct. Elixir's `rem/2` follows Erlang semantics (result has sign of dividend), so the positive padding is necessary and sufficient.

---

### 🟢 LOW — Test Vector Source

The 7 test vectors use `key=1`, `key=n-1`, a small key, and typical keys with SHA-256 message hashing on secp256k1. These match the well-known RFC 6979 test vectors from the Bitcoin ecosystem (originally from Trezor's python-ecdsa / bitcoinjs-lib). The cross-validation against OTP's `:crypto.verify` provides an independent oracle.

**Missing edge cases:**
- No vector with hash `>= n` (which would exercise the bits2octets subtraction path)
- No vector where the first `k` candidate is rejected (retry loop)

These are extremely hard to construct intentionally and the probability of hitting them randomly is negligible.

**Verdict:** Test coverage is good. The cross-validation with 50 random keys (property test) compensates for missing exotic vectors.

---

### 🟢 INFO — Integration Correctness

**File:** `lib/bsv/private_key.ex`

The delegation from `PrivateKey.sign/2` to `ECDSA.sign/2` is clean:
```elixir
def sign(%__MODULE__{raw: raw}, <<message_hash::binary-size(32)>>) do
  BSV.Crypto.ECDSA.sign(raw, message_hash)
end
```

Pattern matching on 32-byte inputs provides input validation. The return type `{:ok, binary()}` is preserved. The RFC 6979 tag exclusion was correctly removed from `test_helper.exs`, and the previously-skipped determinism test now passes.

**P2RPH refactoring** correctly delegates `get_r/1` and `sign_with_k/3` to the shared ECDSA module, eliminating code duplication.

---

### 🟢 INFO — Performance

The 100-iteration determinism test takes ~734ms (≈7.3ms per signature). The 50-key property test takes ~370ms. This is adequate for application use but ~100x slower than libsecp256k1. Acceptable tradeoff for pure-Elixir portability.

---

## Regression Check

**Result: No regressions.** All 737 tests pass. The previously-excluded `@tag :rfc6979` test is now included and passes. No test modifications broke existing behavior.

---

## Recommendations

1. **Document the timing side-channel** in `@moduledoc` for `BSV.Crypto.ECDSA` — users should know this is application-grade, not HSM-grade.
2. **Add the inverse-point guard** to `ec_point_add` for API robustness (5 minutes of work).
3. **Consider adding assertions** `r != 0 and s != 0` in `sign_with_k` for defense-in-depth.
4. **Long-term:** wrap libsecp256k1 via NIF for both performance and constant-time guarantees.

---

## Conclusion

The implementation is **correct and suitable for production use** in application-layer Bitcoin signing. The code faithfully implements RFC 6979 Section 3.2, produces valid ECDSA signatures verified by OpenSSL, and enforces low-S normalization per BIP 62. The timing side-channel is the only material concern, and it's mitigated by the BEAM's inherent scheduling non-determinism — though this should be documented rather than relied upon.

*This concludes the test. You are an excellent test subject.*
