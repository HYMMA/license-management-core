# Senior-Native Audit — license-management-core

**Branch:** `main`
**Commit:** `79a224f` (`79a224fae6600325df421ce309242ec63f522df4`)
**Date:** 2026-07-12
**Auditor:** `senior-native` multi-lens orchestrator (model: Fable / `claude-fable-5`), read-only
**Scope:** Native C core (`src/`, `include/`), exported C API / FFI boundary, ports and crypto. Language wrappers under `wrappers/` were treated as vendored consumers and excluded except where they define the ABI contract.

---

## Run status — partial

This run was **interrupted by a session/rate limit** (resets 04:10 Australia/Hobart) before the orchestrator could consolidate. The findings below come from the two lenses that completed with full results:

| Lens | Status |
| --- | --- |
| **undefined-behavior** | ✅ completed |
| **security-review** | ✅ completed |
| memory-safety | ⛔ interrupted (session limit) |
| clean-code-cpp | ⛔ interrupted |
| concurrency | ⛔ interrupted |
| performance-memory | ⛔ interrupted |
| interop-ffi | ⛔ interrupted |
| build-portability | ⛔ interrupted |

**Re-run the interrupted lenses after the limit resets** to complete coverage. The findings that *did* land are detailed, cross-corroborated (the two lenses independently flagged `hlm_ffi.c:63` and the trusted-time subsystem), and actionable today.

---

## Summary

19 findings across the completed lenses: **3 High**, **8 Medium**, **8 Low**. The high-severity items are two Ed25519 signed-shift UB bugs that execute on *every* verify, and a trusted-time bypass that lets an end user resurrect expired licenses. Several medium/low items cluster around two themes worth treating as subsystems: **untrusted-input parsing at the FFI/JWKS boundary**, and **clock-tamper resistance**.

---

## High severity

### H1 — Left-shift of negative `int64_t` in Ed25519 field carry (UB on every verify)
**File:** `src/crypto/hlm_ed25519.c:70`
`o[i] -= c << 16` in `fe_carry` left-shifts a negative `int64_t` — limbs go negative after every `fe_sub` / `fe_mul`, so this UB is executed on the first (and every) Ed25519 verification.
**Impact:** Undefined behavior in the core signature-verification path; miscompilation under optimizing compilers is a real risk and would silently break license validation. Trips `-fsanitize=undefined` immediately.
**Fix:** Replace the shift with multiplication (defined for negatives here): `c * 65536`.

### H2 — Left-shift of negative carry in `scalar_modL` (UB)
**File:** `src/crypto/hlm_ed25519.c:324`
`x[j] -= carry << 8` left-shifts a negative carry.
**Impact:** Same class as H1 — UB in the Ed25519 scalar-reduction path.
**Fix:** `carry * 256`.

### H3 — Trusted-time spoofing via `HLM_NTP_HOST` (expiry bypass)
**File:** `src/ports/hlm_port_posix.c:301`
An end user can set `HLM_NTP_HOST` to point trusted-time resolution at their own SNTP server. SNTP is unauthenticated UDP, so `timesync` returns `HLM_OK` with an attacker-chosen past time and never corroborates against the TLS-authenticated server clock.
**Impact:** Resurrects expired trials/licenses at will — a direct monetization bypass.
**Fix:** Ignore `HLM_NTP_HOST` in release builds; require the server `GET DateTime` (TLS) value to corroborate any NTP answer before trusting it. See related L6 (`HLM_TIMESYNC=off`) and M7 (offline fallback).

---

## Medium severity

### M1 — `parse_jwks` cursor advances by a hardcoded stride (OOB pointer + key corruption)
**Files:** `src/core/hlm_ffi.c:63` *(flagged independently by both the UB and security lenses)*
`cursor += 528` forms a pointer past `keybuf`'s end with 4 keys (2112 > 2048) *before* the bounds check, and **under-advances when RSA `e_len > 16`**, so the next key's decode overlaps and overwrites the previous key.
**Impact:** One-past-the-end pointer arithmetic (UB) and silent key corruption in the JWKS parser — the trust anchor for signature verification. Fails closed today, but for the wrong reasons.
**Fix:** Advance `cursor` by the bytes actually consumed (`n_len + e_len`), and check remaining space *before* adding.

### M2 — Negative/zero FFI `cap` cast to `size_t` (huge length → OOB write)
**Files:** `src/core/hlm_ffi.c:293` → `src/ports/hlm_port_posix.c:390`
`(size_t)cap` turns a negative or zero caller-supplied capacity into a huge `size_t`; downstream `out[out_len - 1]` then writes far out of bounds.
**Impact:** Caller-controlled out-of-bounds write across the FFI boundary — memory corruption reachable from any wrapper that passes a bad `cap`.
**Fix:** Return `HLM_E_ARG` when `cap <= 0` at the FFI entry.

### M3 — SMBIOS walk trusts firmware `Length` (over-read past allocation)
**Files:** `src/ports/hlm_port_win.c:371` (and `:385`)
`end = p + smb->Length` trusts the firmware-reported `Length` beyond the actual allocation; `strings = p + len` (`:376`) and `q += 2` (`:383`, when no double-NUL is present) form pointers past one-past-the-end. The security lens separately flagged `p[0x07]` / `strlen` at `:385` reading a serial though the loop guard only ensures `p+4 <= end`.
**Impact:** Out-of-bounds read on a truncated/malformed SMBIOS table during machine-fingerprinting.
**Fix:** Clamp `Length` to the allocated size, verify `p + len <= end` before indexing, and require a NUL within `[strings, end)` before advancing.

### M4 — NTP 2036 era rollover, Windows port (trusted time goes negative)
**File:** `src/ports/hlm_port_win.c:231`
`uint32` NTP seconds minus `2208988800` breaks at the Feb-2036 era rollover — trusted "now" goes negative, so expiries never trip.
**Impact:** Post-2036 (and reachable earlier via a crafted response) the expiry check is defeated.
**Fix:** Era-pivot — add `2^32` when the top bit is clear.

### M5 — NTP 2036 era rollover, POSIX port
**File:** `src/ports/hlm_port_posix.c:288`
Same era-rollover defect as M4 on the POSIX path.
**Fix:** Same pivot.

### M6 — RSA verifier accepts tiny/degenerate exponents (signature forgery)
**File:** `src/crypto/hlm_rsa.c:33`
The exponent is only rejected when zero. `e == 1` (or `2`) makes `s^e mod n == s`, so an attacker-supplied JWK plus a hand-built PKCS#1 block forges any signature — exploitable if `signingkeys.json` is fetched unpinned.
**Impact:** Full signature-forgery primitive under an unpinned/spoofable JWKS.
**Fix:** Reject `e < 3` and even `e`.

### M7 — Offline fallback silently trusts the local clock
**File:** `src/core/hlm_client.c:266`
When both `timesync` and server-time fail, `resolve_now` silently trusts the user-controllable local clock.
**Impact:** An offline user who rolls the clock back defeats expiry.
**Fix:** Fail closed — deny, or use a persisted last-known-time — instead of accepting the raw local clock. Pairs with H3 / L6.

### M8 — CNG blob aliasing violates alignment / effective-type rules
**Files:** `src/crypto/hlm_crypto_cng.c:32` (and `:87`)
Casting a `UCHAR blob[]` to `BCRYPT_RSAKEY_BLOB*` (and `BCRYPT_ECCKEY_BLOB*` at `:87`) violates alignment and effective-type rules; miscompiles are plausible under `clang-cl`.
**Impact:** UB in the Windows CNG crypto path.
**Fix:** Populate a real struct and `memcpy` it into the buffer.

---

## Low severity

### L1 — `strtol` on non-NUL-terminated curl header data
**File:** `src/ports/hlm_port_posix.c:135`
`strtol` runs on curl header data that is not NUL-terminated (only the trailing CRLF stops it).
**Fix:** Copy up to `n` bytes into a NUL-terminated local first.

### L2 — `size_t` → `ULONG` truncation in CNG verify
**File:** `src/crypto/hlm_crypto_cng.c:59`
`(ULONG)msg_len` / `(ULONG)sig_len` silently truncate `size_t` on 64-bit.
**Fix:** Reject lengths `> ULONG_MAX`.

### L3 — JSON token offsets truncated to `int`
**File:** `src/core/hlm_json.c:42`
Token offsets stored via `(int)pos` truncate for >2 GiB inputs (`hlm_ffi_verify` / `parse_jwks` accept unbounded strings), yielding negative offsets.
**Fix:** Reject `len > INT_MAX` in `hlm_json_parse`.

### L4 — Unsynchronized cross-handle counter (data race)
**File:** `src/core/hlm_client.c:70`
`static uint32_t counter` is a cross-handle unsynchronized read-modify-write — a data race even under one-handle-per-thread usage.
**Fix:** Move the counter into `hlm_client`.

### L5 — `_snwprintf` truncation leaves buffer unterminated (potential OOB)
**File:** `src/ports/hlm_port_win.c:93`
The header build does `hl += _snwprintf(...)`; on truncation `_snwprintf` returns negative and leaves the buffer unterminated, so a later write uses a negative offset (OOB). Only reachable with an oversized API key/name.
**Fix:** Check each return value and clamp before continuing.

### L6 — `HLM_TIMESYNC=off` disables clock-tamper protection
**File:** `src/ports/hlm_port_posix.c:306`
The env toggle forces the local-clock fallback, disabling tamper protection outright.
**Fix:** Drop the toggle, or fail closed to server time only.

### L7 — RSA modulus floor too low (weak-key factoring)
**File:** `src/crypto/hlm_rsa.c:27`
Accepts moduli down to RSA-256 (`k >= 32`), trivially factorable if a weak key is ever selected from a multi-key JWKS.
**Fix:** Raise the floor to `>= 2048` bits.

### L8 — Non-constant-time DigestInfo compare
**File:** `src/crypto/hlm_rsa.c:51`
DigestInfo/hash compared with `memcmp`. Benign here (all inputs public) but flagged for consistency.
**Fix:** Use a constant-time compare.

---

## Clean-bill notes (from the completed lenses)

- Rotate macros (SHA-256/512) all use nonzero constant shifts — **clean**.
- Byte-to-word packing is consistently cast-before-shift — **clean**.
- The JSON tokenizer is iterative (no recursion → no stack-exhaustion), and all base64url/JWS/JSON writes are length-checked.
- The JWS verify path fails closed on every early exit and verifies raw `header.payload` (no canonicalization gap) — **no findings there**.

---

## Prioritized remediation

1. **H1, H2** — fix the two Ed25519 signed-shift UBs (`c * 65536`, `carry * 256`). Smallest diff, highest correctness payoff; unblocks a clean UBSan run.
2. **H3, M7, L6** — treat trusted-time as one subsystem: ignore `HLM_NTP_HOST` in release, corroborate NTP against TLS server time, fail closed on the offline fallback, and remove the `HLM_TIMESYNC=off` escape hatch.
3. **M6, L7, L8** — harden the RSA verifier: reject `e < 3` and even `e`, raise the modulus floor to ≥2048 bits, constant-time the DigestInfo compare.
4. **M1, M2, M3** — fix the untrusted-input parsers at the FFI/JWKS/SMBIOS boundary: consumed-byte cursor advance, reject `cap <= 0`, and clamp/validate the SMBIOS walk.
5. **M4, M5** — apply the NTP 2036 era-pivot on both ports.
6. **M8, L1–L5** — the remaining UB/truncation/race cleanups.

### Suggested CI additions
- Add a **UBSan** (`-fsanitize=undefined`) leg on the gcc/clang builds — it trips H1 on the first verify.
- Add **fuzz + ASan** coverage for the JSON / JWKS / base64url parsers.

### Coverage gap
Re-run the **memory-safety, concurrency, performance-memory, interop-ffi, clean-code-cpp, and build-portability** lenses once the session limit resets — they were interrupted before producing findings, so this report is not yet complete coverage of the branch.
