# Senior-Native Audit — license-management-core

**Branch:** `main`
**Commit:** `79a224f` (`79a224fae6600325df421ce309242ec63f522df4`)
**Date:** 2026-07-12
**Auditor:** `senior-native` multi-lens orchestrator (model: Fable / `claude-fable-5`), read-only
**Scope:** Native C core (`src/`, `include/`), exported C API / FFI boundary, ports and crypto. Language wrappers under `wrappers/` were treated as vendored consumers and excluded except where they define the ABI contract.

---

## Run status — complete (all 8 lenses)

The first run (2026-07-12) completed the **undefined-behavior** and **security-review** lenses before a session limit interrupted it; the remaining six lenses were re-run on 2026-07-13 and are now folded in below. All eight lenses have reported.

| Lens | Status | Section |
| --- | --- | --- |
| **undefined-behavior** | ✅ completed | High/Medium/Low findings below |
| **security-review** | ✅ completed | High/Medium/Low findings below |
| **memory-safety** | ✅ completed | [Supplement](#memory-safety) |
| **concurrency** | ✅ completed | [Supplement](#concurrency) |
| **interop-ffi** | ✅ completed | [Supplement](#interop-ffi) |
| **performance-memory** | ✅ completed | [Supplement](#performance-memory) |
| **clean-code-cpp** | ✅ completed | [Supplement](#clean-code-cpp) |
| **build-portability** | ✅ completed | [Supplement](#build-portability) |

The first two lenses cross-corroborated (both independently flagged `hlm_ffi.c:63` and the trusted-time subsystem). The supplementary six added **three more High-severity findings** — two concurrency (thread-unsafe libcurl bring-up) and one build-portability (the entire internal ABI is accidentally exported).

---

## Summary

**Part 1 — undefined-behavior + security-review (below):** 19 findings — **3 High**, **8 Medium**, **8 Low**. The highs are two Ed25519 signed-shift UB bugs that execute on *every* verify, and a trusted-time bypass that lets an end user resurrect expired licenses.

**Part 2 — the six supplementary lenses ([Supplement](#supplementary-lenses-six-lens-completion)):** three more **High** findings and a broad set of Medium/Low items — the flagship being **thread-unsafe libcurl initialization** that can crash or leak in every multithreaded host (JVM/Node/.NET/Go/Python), and an **accidentally-public ABI** (all internal `hlm_bn_*`/`hlm_sha256_*`/JSON helpers exported).

Findings cluster around a few subsystems worth treating as units: **untrusted-input parsing at the FFI/JWKS/SMBIOS boundary**, **clock-tamper resistance**, **thread-safe I/O bring-up (libcurl / Winsock / cache writes)**, and **ABI/export hygiene ahead of a 1.0 tag**. The combined, cross-lens priority list is in [Prioritized remediation](#prioritized-remediation) at the end.

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

# Supplementary lenses (six-lens completion)

*Run 2026-07-13 on Fable. Scope: canonical C99 core (`src/`, `include/`, `tools/`, `tests/`) plus the FFI wrapper boundary; vendored `wrappers/go/*.c` and `wrappers/rust/csrc/**` excluded (byte-identical copies). None of the findings below duplicate the undefined-behavior / security-review findings above.*

## memory-safety

The core untrusted paths (JSON tokenizer, Base64URL, bignum, RSA/P-256/Ed25519, SHA) are **clean** under this lens — every decoder write and token accessor is length-/range-checked, and every `hlm_json_string` caller handles the `(size_t)-1` error. Residual issues live only in the ports and tests.

- `src/ports/hlm_port_posix.c:390` · **low** · `hlm_machine_name_posix` writes `out[out_len-1]='\0'` unconditionally; `out_len==0` (reachable via `hlm_ffi_machine_name(out,0)`) is an `out[-1]` underflow write, and macOS `gethostname(out,0)` may return success. *Impact:* 1-byte OOB write when a wrapper passes cap 0. *Fix:* `if (out_len==0) return HLM_E_ARG;` before the terminator.
- `src/ports/hlm_port_win.c:389` · **low** · `smbios_string` can `return p` for a run reaching `end` without a NUL; the caller's `strlen` then reads past the `HeapAlloc` buffer. *Impact:* heap over-read → garbage serial / info leak / crash (distinct mechanism from the `:371` over-read above). *Fix:* return NULL when no terminator is found within the span.
- `tests/hlm_tests.c:369` (also `:371,:394,:396,:398`) · **low** · `n = hlm_json_string(...)` fed to `hlm_sha256`/`strcmp`/`strlen` without checking `n==(size_t)-1`. *Impact:* `SIZE_MAX`-length OOB read on a malformed vector (test-only, trusted input). *Fix:* bail when the return is `(size_t)-1`.

## concurrency

The per-handle model (`last_error`, `eval_now`, `resp`, `buf` are all correctly per-handle; stateless `hlm_ffi_verify` uses stack buffers) is sound under the documented "one handle per thread" contract. The breaks are **process-global** side effects that violate that contract regardless.

- `src/ports/hlm_port_posix.c:83` · **high** · `curl_load()` fills the process-global `g_curl` (dlopen handle + 7 function pointers) behind a bare non-atomic `if (g_curl.handle != NULL)`. *Impact:* two threads first-using HTTP race → duplicate `dlopen` (handle leak) and, on weakly-ordered CPUs, a reader sees `handle!=NULL` before the pointer stores publish → NULL/torn `easy_init` call; the failure-path `memset(&g_curl,0)` can zero the struct under a concurrent user → crash. *Fix:* gate with `pthread_once`/`call_once`, or release-store `handle` last and acquire-load it.
- `src/ports/hlm_port_posix.c:157` · **high** · `curl_send` calls `easy_init` with no prior `curl_global_init`, so the first concurrent calls hit libcurl's non-thread-safe implicit global/TLS-backend (OpenSSL/GnuTLS) init. *Impact:* race/crash during backend init in exactly the multithreaded hosts (JVM/Node/Python). *Fix:* call `curl_global_init(CURL_GLOBAL_DEFAULT)` once inside the same `call_once`. *(Portability angle also flagged by build-portability `:74`.)*
- `src/ports/hlm_port_posix.c:300` · **medium** · `timesync_posix_now` holds the `getenv("HLM_NTP_HOST")` pointer across `sntp_query`; `getenv` isn't safe against a host thread's `setenv/putenv` reallocating `environ`. *Impact:* dangling read → crash / wrong NTP host. *Fix:* copy the value into a local immediately.
- `src/ports/hlm_ports_common.c:47` · **medium** · `file_write` does `fopen(path,"wb")` (truncate-in-place, no temp+rename). *Impact:* two handles sharing one `license_path` let a reader observe a half-written cache; a crash mid-write leaves a truncated `.lic`. *Fix:* write `path.tmp` then `rename()`.
- `src/ports/hlm_port_posix.c:236` · **medium** · `sleep_posix` uses `nanosleep(&ts,NULL)` with no EINTR retry. *Impact:* a signal (Go SIGURG preemption, JVM signals) truncates the retry/backoff wait. *Fix:* loop on EINTR via `rem`, or `clock_nanosleep(TIMER_ABSTIME)`.
- `src/ports/hlm_port_win.c:200` · **low** · every `sntp_query` calls `WSAStartup`/`WSACleanup` on the process-global Winsock refcount. *Impact:* refcount-safe alone, but teardown timing is fragile alongside a host that also manages Winsock. *Fix:* one `WSAStartup` at load via `call_once`; drop the per-query cleanup.

## interop-ffi

Contract baseline confirmed: `hlm_status`=0–6, format=1/2/3, `hlm_err`=0/−1…−15; string accessors return handle-owned UTF-8, never NULL (they return `""`); `machine_id/name(out,cap)` return 0/negative and need ≥53 bytes. **Java, Rust, Go, and Node are clean** — calling convention, type widths, enum values, UTF-8 marshalling both ways, immediate copy-of-returned-strings, input-string freeing on every path, `cap` handling, and NULL-handle detection all correct.

- `wrappers/dotnet/LicenseManagement.Core/NativeMethods.cs:97` · **medium** · Every input param is `[MarshalAs(LPStr)]` and every return uses `Marshal.PtrToStringAnsi`, but the C ABI is UTF-8 (WinHTTP does `MultiByteToWideChar(CP_UTF8,…)`). *Impact:* non-ASCII product names, buyer emails, metadata, `last_error_detail`, and `machine_name` are silently corrupted to mojibake/`?` for all .NET consumers. *Fix:* switch params to `UnmanagedType.LPUTF8Str` and returns to `Marshal.PtrToStringUTF8` (`GetMachineId`'s ASCII is fine).
- `wrappers/python/hymmalm/__init__.py:332` (also `:104,:335,:338,:363`) · **low** · String accessors call `.decode()` on the `c_char_p` result with no NULL guard — the only wrapper lacking it. *Impact:* safe today (C returns `""`), but a future NULL-returning accessor raises `AttributeError` where peers yield `""`. *Fix:* `(... or b"").decode()`.
- `wrappers/php/src/LicenseClient.php:161` (also `:271`) · **low** · `LicenseStatus::from()` throws `ValueError` on an out-of-enum code instead of mapping to `Unknown`, contradicting the tolerant `fromCode` other wrappers use deliberately. *Impact:* a future added status code would throw instead of degrading (can't fire against today's 0–6). *Fix:* `LicenseStatus::tryFrom($v) ?? LicenseStatus::Unknown`.

## performance-memory

The core follows a strict "no heap alloc, no rescans, fixed buffers" discipline — single-pass tokenizer, `snprintf` into stack buffers, one `calloc` per handle. Documented speed/reviewability tradeoffs (schoolbook modexp, non-windowed P-256, constant-time Ed25519 ladder) were correctly left alone. Genuine exceptions:

- `src/ports/hlm_port_posix.c:157` · **medium** · `easy_init`/`easy_cleanup` per HTTP call. *Impact:* the 4 same-host requests in one `refresh_internal` each pay a fresh TCP/TLS handshake. *Fix:* cache one easy handle (or a connection cache) on the client, freed at destroy.
- `src/ports/hlm_port_win.c:71` · **medium** · new session/connect/request handle set per call. *Impact:* defeats WinHTTP keep-alive; re-handshakes the same repeated sequence. *Fix:* persist one session (+ per-host connect) on the client and reuse.
- `src/core/hlm_bignum.c:99` (also `:174,:194,:210,:220,:260`) · **medium** · `hlm_bn_zero/add/sub/mod/modmul/copy` memset/memcpy the full 128-limb (512 B) capacity regardless of size. *Impact:* P-256's 8-limb operands move ~16× more memory than needed across the ~1500 bignum calls per verify. *Fix:* size the op to the operand's `n`/`mn` limbs (not constant-time-sensitive — limb count tracks the public modulus).
- `src/core/hlm_client.c:342` · **low** · `ensure_computer` calls `strlen(c->resp)` twice. *Impact:* trivial redundant scan. *Fix:* hoist into one local, as sibling call sites do.
- `src/core/hlm_jws.c:141` · **low** · `jwk_decode_member` unescapes each member into a 1024-byte temp before base64url-decoding, though b64url text never needs JSON unescaping. *Impact:* an extra copy per JWK member. *Fix:* base64url-decode directly from the `hlm_json_raw` span.

## clean-code-cpp

Bignum, SHA-256, RSA, `crypto_portable`, and `ports_common` are exemplary (const-correctness, internal linkage). Discovered skills `clean-code`/`design-patterns` were C#/.NET-specific, so only their language-agnostic smells (dead code, duplication, magic numbers) applied. Findings, grouped by file:

- `include/hymma/hlm_ffi.h:44` / `src/core/hlm_ffi.c:82` · **medium** · 9 positional params on `hlm_ffi_create`, easy to transpose across FFI (`machine_id`/`machine_name`, `format`/`valid_days`). *Impact:* silent misconfiguration at the boundary. *Fix:* add an additive `hlm_ffi_create_opts(const struct*)` variant (keep the ABI).
- `src/core/hlm_ffi.c:112-136,290-306` · **medium** · the machine-id/name platform dispatch is copy-pasted 4×; `hlm_ffi_create` is ~96 lines (`:82`, **low**). *Fix:* extract `static ffi_resolve_machine_id/_name`; split create.
- `src/core/hlm_client.c:95` (+`:331,:337,:366,:384,:482`) · **medium** · HTTP status codes are raw literals and the `200..299` success test is duplicated 5×. *Impact:* error-classification drift. *Fix:* named codes + `static int http_is_success(int)`. `:487-522` **medium**: `activate`/`deactivate` near-identical → extract shared helper. `hlm.h:380` **low**: `char last_error[256]` bare literal → `HLM_MAX_ERROR_DETAIL`.
- `src/core/hlm_json.c:101` · **medium** · `hlm_json_parse` is a ~112-line inline state machine → split case arms into `static` handlers. `:34` (+~15 sites) **medium**: raw `-1/-2/-3` tokenizer errors → named enum. `hlm_json.h:32` **low**: `toks` non-const defeats `const` accessors → `const hlm_json_tok *toks`.
- `src/core/hlm_license.c:67` · **medium** · `hlm_license_parse` ~108 lines → per-section `static` helpers. `:96` **low**: `char status[32]` bare literal.
- `src/core/hlm_jws.c:47-50` · **medium** · scratch buffers are magic numbers incl. an unexplained `sig[512+8]` → name + comment. `:132` **low**: `jwk_decode_member` has 4 output-ish params → return a `{ptr,len}` struct.
- `src/core/hlm_sha512.h:1` · **medium** · **missing `extern "C"` guard** (unlike `hlm_sha256.h`) → C++ consumers get link errors. `:11` **medium**: 128/64/112 hardcoded → add `HLM_SHA512_BLOCK/DIGEST_SIZE`. `hlm_sha512.c:39` **low**: helper `compress` vs sibling `sha256_compress` → rename.
- `src/crypto/hlm_ed25519.h:1` · **medium** · **missing `extern "C"` guard**. `hlm_ed25519.c:199` **low**: `point_add` never writes `q` → `const gf q[4]`.
- `src/crypto/hlm_crypto_cng.c:55,102` · **medium** · identical SHA-256 open/hash/close block → extract `static NTSTATUS cng_sha256(...)`. `:28` **low**: `32` literal → `HLM_SHA256_DIGEST_SIZE`. `:29` **low**: dead `cb` variable → delete.
- `src/crypto/hlm_p256.c:205,261` · **low** · Fermat-inverse three-liner duplicated → extract `bn_mod_inverse_fermat`.
- `src/ports/hlm_port_win.c:45` · **medium** · `winhttp_send` ~114 lines → split header-build and body-read. `:49` vs `:59` **medium**: wide-char buffer capacities duplicated as bare literals between declaration and call → pass `sizeof(buf)/sizeof(buf[0])` so a resize can't desync into overflow. `:365,:399` **low**: `smbios_baseboard_serial` duplicates `HeapFree` at two returns → `goto done`.
- `src/ports/hlm_port_posix.c:34-36,252` vs `hlm_port_win.c:31-33,192` · **medium** · SNTP packet encode/decode and the timeout/drift `#define`s are duplicated verbatim between ports → lift the packet build/parse into `hlm_ports_common.c` (leave the socket I/O per-platform).
- `tools/machineid.c:10` · **medium** · `char id[64], name[128]` hardcodes the current `HLM_MAX_MACHINE_ID`/`HLM_MAX_NAME` values → use the macros so they can't drift from the public limits.

## build-portability

Endianness is **clean** — SHA-256/512 and bignum byte↔word conversions are explicit shifts (portable to big-endian); b64url and `hlm.h` clean; format specifiers have no MSVC/gcc mismatch; `.gitattributes (* text=lf)` neutralizes line-ending drift.

- `CMakeLists.txt:55` · **high** · `WINDOWS_EXPORT_ALL_SYMBOLS ON` + `C_VISIBILITY_PRESET default` export **every** non-static internal helper (`hlm_bn_*`, `hlm_sha256_*`, JSON internals) as public ABI on Windows and ELF/Mach-O. *Impact:* consumers can bind internals and break on any refactor; the intended surface is only `hlm_ffi_*`. *Fix:* `C_VISIBILITY_PRESET hidden`, drop `WINDOWS_EXPORT_ALL_SYMBOLS`, export only `hlm_ffi_*` via a real macro.
- `include/hymma/hlm_ffi.h:20` · **medium** · `HLM_API` is **dead** — `HLM_FFI_BUILD_DLL` is defined by no target (repo-wide grep), so the annotation is always empty. *Impact:* misleading; all Windows exporting is done by the all-symbols flag. *Fix:* `target_compile_definitions(hymmalm PRIVATE HLM_FFI_BUILD_DLL)` paired with the visibility fix.
- `CMakeLists.txt:1` · **medium** · No `install()`/`export()` targets; CI hand-copies with `find`+`cp`. *Impact:* library can't be consumed via `find_package()`. *Fix:* `install(TARGETS … EXPORT)` + header install + generated `hymmalmConfig.cmake`.
- `CMakeLists.txt:9` · **medium** · No `-Werror`/`/WX`, no hardening (`_FORTIFY_SOURCE=2`, stack protector, `/guard:cf`, `/Qspectre`), no ASan/UBSan CI leg; global `_CRT_SECURE_NO_WARNINGS` masks unsafe-CRT diagnostics for every target. *Impact:* latent memory/UB bugs uncaught in a crypto/parsing library. *Fix:* add a warnings-as-errors + sanitizer CI leg; scope the CRT define to where it's needed.
- `.github/workflows/ci.yml:86` · **medium** · The `wrappers` job (incl. go/rust) runs only on `ubuntu-latest`, so the Windows-only vendored files (`hlm_port_win.c`, `hlm_crypto_cng.c`) never compile under the wrapper's Windows toolchain. *Impact:* `git diff --exit-code` proves text parity, not buildability. *Fix:* add a `windows-latest` compile-only leg to the go/rust matrix.
- `src/ports/hlm_port_posix.c:74` · **medium** · No `curl_global_init` before `easy_init` across the dlopened OpenSSL/GnuTLS libcurl flavors. *Impact:* unsafe implicit lazy init (same root as concurrency `:157`). *Fix:* `dlsym` + call `curl_global_init` once, guarded.
- `src/ports/hlm_port_posix.c:1` · **low** · No `_POSIX_C_SOURCE`/`_DEFAULT_SOURCE`; `nanosleep`/`getaddrinfo`/`gethostname` stay visible only because CMake never sets `CMAKE_C_EXTENSIONS OFF` (implicit `-std=gnu99`). *Impact:* breaks under strict `-std=c99`. *Fix:* `#define _POSIX_C_SOURCE 200809L` (`_DARWIN_C_SOURCE` on macOS) at the top.
- `wrappers/go/sync-csrc.sh:15` · **low** · Vendoring globs `*.c`/`*.h` and cgo compiles every `.c`, while CMake/`build.rs` use explicit lists. *Impact:* a new src file added without updating those lists compiles into Go only, undetected by the diff guard. *Fix:* CI cross-diff the vendored set against `HLM_CORE_SOURCES`.
- `src/ports/hlm_port_win.c:92` · **low** · Header build uses legacy `_snwprintf` (returns −1 / no NUL on truncation) and `hl += _snwprintf(...)` is unchecked. *Impact:* current field caps prevent truncation, but the invariant is fragile if a field grows. *Fix:* `_snwprintf_s(…,_TRUNCATE,…)` or check the return and NUL-terminate.

---

## Prioritized remediation

### Part 1 — UB & security (from the first-run lenses)
1. **H1, H2** — fix the two Ed25519 signed-shift UBs (`c * 65536`, `carry * 256`). Smallest diff, highest correctness payoff; unblocks a clean UBSan run.
2. **H3, M7, L6** — treat trusted-time as one subsystem: ignore `HLM_NTP_HOST` in release, corroborate NTP against TLS server time, fail closed on the offline fallback, and remove the `HLM_TIMESYNC=off` escape hatch.
3. **M6, L7, L8** — harden the RSA verifier: reject `e < 3` and even `e`, raise the modulus floor to ≥2048 bits, constant-time the DigestInfo compare.
4. **M1, M2, M3** — fix the untrusted-input parsers at the FFI/JWKS/SMBIOS boundary: consumed-byte cursor advance, reject `cap <= 0`, and clamp/validate the SMBIOS walk.
5. **M4, M5** — apply the NTP 2036 era-pivot on both ports.
6. **M8, L1–L5** — the remaining UB/truncation/race cleanups.

### Part 2 — from the six supplementary lenses (by leverage)
1. **Thread-safe libcurl bring-up** (`hlm_port_posix.c:83` + `:157`, concurrency high / build-portability `:74`) — gate `curl_load` behind `pthread_once`/`call_once` and add a one-time `curl_global_init(CURL_GLOBAL_DEFAULT)`. The flagship correctness bug: crash / handle-leak / torn-init in every multithreaded host (JVM, Node, .NET, Go, Python).
2. **Lock down the exported ABI** (`CMakeLists.txt:55` + `hlm_ffi.h:20`, build-portability high) — hidden visibility + a real `HLM_API`/`HLM_FFI_BUILD_DLL` so only `hlm_ffi_*` is exported. Do this **before a 1.0 tag**, while the accidental surface can still be removed without breaking consumers.
3. **Fix .NET UTF-8 marshalling** (`NativeMethods.cs:97`, interop medium) — `LPUTF8Str` + `PtrToStringUTF8`. Small change that stops silent data corruption of every non-ASCII field for all NuGet consumers.
4. **Atomic license-cache writes** (`hlm_ports_common.c:47`, concurrency medium) — temp-file + `rename()` to prevent torn/truncated `.lic` under shared paths or crashes.
5. **Reuse HTTP connections** (`hlm_port_posix.c:157` / `hlm_port_win.c:71`, performance medium) — persist one easy/WinHTTP handle on the client; removes ~4× TCP/TLS handshakes per refresh.
6. **Cheap hardening cluster** — `out_len==0` guard (`hlm_port_posix.c:390`), SMBIOS terminator check (`hlm_port_win.c:389`), EINTR loop (`:236`), `getenv` copy (`:300`); add the missing `extern "C"` guards on `hlm_sha512.h`/`hlm_ed25519.h`; and add a `-Werror` + ASan/UBSan CI leg (`CMakeLists.txt:9`) to catch the next such bug automatically.

### Suggested CI additions
- Add a **UBSan** (`-fsanitize=undefined`) + **ASan** leg on the gcc/clang builds — UBSan trips H1 on the first verify; ASan would catch the concurrency/memory items under a threaded stress test.
- Add **fuzz** coverage for the JSON / JWKS / base64url parsers.
- Add a **`windows-latest` compile-only leg** to the go/rust wrapper matrix so the Windows-only vendored sources actually build (build-portability `ci.yml:86`).
- Consider a **ThreadSanitizer** leg exercising two concurrent handles to lock in the libcurl/Winsock fixes.

### Coverage
All eight lenses have now reported — this is complete coverage of branch `main` @ `79a224f` (undefined-behavior, security-review, memory-safety, concurrency, interop-ffi, performance-memory, clean-code-cpp, build-portability).
