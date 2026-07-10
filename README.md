# license-management-core

[![CI](https://github.com/HYMMA/license-management-core/actions/workflows/ci.yml/badge.svg)](https://github.com/HYMMA/license-management-core/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**One portable C library that is the source of truth for License-Management.com
client behavior on every platform — desktops, servers, and IoT devices —
with thin language wrappers on top.**

This is the architecture the established licensing vendors use. Cryptlex
LexActivator is a native C library with P/Invoke//ctypes//JNI//cgo wrappers for
.NET, Java, Python, Node, Go, Delphi and more; Wibu CodeMeter ships one native
Core API bound from "almost all common programming languages" plus a static-C
`CodeMeter Embedded` subset and a `µEmbedded` source-code SDK for MCUs; Thales
Sentinel and Nalpeiron Zentitle2 follow the same pattern. Implement the
security-critical logic once, in C, and every SDK inherits identical behavior.

```
                    ┌───────────────────────────────────────────┐
   .NET  Python     │              hymmalm (C99)                │
   Java  Node  Go   │                                           │
   C++   Rust  ...  │  JWS verify (RS256 / ES256 / EdDSA*)      │
        │           │  license model + status state machine     │
        ▼           │  machine fingerprint (SDK-compatible)     │
  hlm_ffi.h flat    │  REST client flow (register → license →   │
  C ABI  ──────────►│  activate/deactivate), offline cache      │
                    ├───────────────────────────────────────────┤
                    │  PORTS (replaceable per platform)         │
                    │  crypto   http    storage   clock   id    │
                    │  ────────────────────────────────────     │
                    │  portable WinHTTP file      time()  SMBIOS│  ← built-in
                    │  CNG      (yours) (flash)   (RTC)  (UID)  │  ← you plug in
                    └───────────────────────────────────────────┘
```

## Why this exists

The .NET `LicenseManagement.EndUser` SDK covers .NET Framework and .NET on
Windows — nothing else. Using licensing from a C++ app (CadShiftNesting), a
Linux daemon, or a bare-metal water meter previously meant re-implementing the
flow by hand. This core:

- **verifies the portable license formats** the server already emits
  (`GET /api/license?format=jws|es256|eddsa` — compact JWS instead of
  .NET-only enveloped XML-DSig);
- **speaks the same REST contract** as the .NET SDK (same endpoints, headers,
  idempotency keys, `PUB_` client keys);
- **produces the same machine fingerprint** as the .NET SDK's DeviceId
  pipeline (SHA-256 of `{BaseBoardSerial},{ProcessorId}` → Crockford Base32),
  so one physical machine is ONE computer on the server regardless of which
  SDK the app uses — no double registration, no double billing;
- **runs on anything**: C99, zero dependencies, zero heap allocation in the
  core (`malloc` appears only in the optional FFI layer), all OS access
  behind five small ports.

## The IoT / embedded story

A fully offline device needs only the low-level API — no HTTP port, no
storage port, no OS:

```c
#include "hymma/hlm.h"

/* baked in at manufacture: the vendor's public key (from /api/signingkeys.json)
   and the license file provisioned onto the device */
static const uint8_t EC_X[32] = { /* ... */ }, EC_Y[32] = { /* ... */ };

int license_ok(const char *jws, size_t jws_len, int64_t rtc_now)
{
    hlm_public_key key = { HLM_ALG_ES256 };
    hlm_crypto crypto = hlm_crypto_portable();
    hlm_license lic;
    hlm_status status;
    char my_id[64];
    const char *uid = read_mcu_unique_id();      /* your one line of glue  */

    key.u.ec.x = EC_X;
    key.u.ec.y = EC_Y;
    hlm_fingerprint(&uid, 1, my_id, sizeof(my_id));

    return hlm_license_check(jws, jws_len, &key, 1, &crypto,
                             "PRD_...", my_id, rtc_now,
                             &lic, &status) == HLM_OK
        && (status == HLM_STATUS_VALID || status == HLM_STATUS_VALID_TRIAL);
}
```

ES256 signatures are 64 bytes and verify with the built-in portable P-256
code — no mbedTLS, no OpenSSL. For ES256-only builds you can shrink the
bignum arena with `-DHLM_BN_MAX_LIMBS=16`. A connected device adds an
`hlm_http` implementation over its TCP stack and gets the full client flow.

## Desktop quick start (C)

```c
hlm_client *c = malloc(sizeof(*c));          /* 32 KB workspace, or static */
hlm_client_cfg cfg = {0};
char machine_id[64], machine_name[128];

hlm_machine_id_win(machine_id, sizeof(machine_id));
hlm_machine_name_win(machine_name, sizeof(machine_name));

cfg.product_id     = "PRD_01KWWPEPM0N070BDAHJ7G09RGV";
cfg.client_api_key = "PUB_...";              /* never a MST_ key            */
cfg.format         = HLM_ALG_ES256;          /* or HLM_ALG_RS256            */
cfg.keys           = keys;                   /* parsed with hlm_jwk_parse() */
cfg.key_count      = nkeys;
cfg.machine_id     = machine_id;
cfg.machine_name   = machine_name;
cfg.crypto         = hlm_crypto_portable();  /* or hlm_crypto_cng()         */
cfg.http           = hlm_http_winhttp();
cfg.storage        = hlm_storage_file(&(hlm_storage_file_cfg){ .path = lic_path });

hlm_client_init(c, &cfg);
hlm_client_check(c);                         /* silent check + trial bootstrap */
/* c->status: HLM_STATUS_VALID / VALID_TRIAL / INVALID_TRIAL / ...          */

hlm_client_activate(c, receipt_code);        /* attach a purchase           */
```

## .NET wrapper (the reference binding)

`wrappers/dotnet/LicenseManagement.Core` shows the wrapper pattern every language
follows — bind the flat ABI in `include/hymma/hlm_ffi.h`, marshal strings,
add an idiomatic facade:

```csharp
using var client = new LicenseClient(new LicenseClientOptions
{
    ProductId    = "PRD_01KWWPEPM0N070BDAHJ7G09RGV",
    ClientApiKey = "PUB_...",
    JwksJson     = File.ReadAllText("signingkeys.json"), // or bake it in
    Format       = SignedFormat.Es256,
    LicensePath  = licPath,
});

var status = client.Check();        // trial bootstrap on first run
if (status == LicenseStatus.InvalidTrial)
    client.Activate(userEnteredReceiptCode);
```

Wrapping from other languages is the same ~hundred lines: Python `ctypes`,
Java JNA, Node `koffi`, Go `cgo`, Rust `bindgen` — see `hlm_ffi.h`, which is
deliberately strings-and-ints only.

## Building

```bash
cmake -S . -B build            # MSVC, clang or gcc; nothing to vendor
cmake --build build
build/hlm_tests tests/vectors/vectors.json
```

Targets: `hymmalm.dll`/`.so` (for wrappers), `libhymmalm.a` (for embedding),
`hlm_tests`, `hlm_machineid` (prints this machine's fingerprint — compare it
with the .NET SDK's DeviceId output).

## Testing & the compatibility guarantee

`tools/vectorgen` is a .NET program containing a byte-for-byte copy of the
license server's `JwsLicenseSigner.BuildCompactJws` plus payloads shaped like
`LicenseGetApiModel`. It generates `tests/vectors/vectors.json`: RS256 and
ES256 tokens, expected statuses at fixed clock times, and tampered variants.

The C test suite verifies every vector with the portable crypto **and** with
Windows CNG, so the from-scratch RSA/P-256 verifiers are cross-checked against
the OS implementation on every run. The .NET demo
(`wrappers/dotnet/LicenseManagement.Core.Demo`) runs the same vectors through
P/Invoke. If these are green, the core verifies exactly what production signs.

Regenerate vectors after a server-side signing change:

```bash
cd tools/vectorgen && dotnet run -c Release -- ../../tests/vectors/vectors.json
```

## Wire contract (pinned by this repo)

| Operation | Call |
|---|---|
| Register computer | `POST computer` `{"MacAddress","Name"}` (201/409 = ok, idempotent) |
| Resolve computer | `GET computer?macAddress={fingerprint}` |
| Create license | `POST license` `{"Product","Computer"}` (201/409 = ok, idempotent) |
| Fetch signed license | `GET license?computer=&product=&validDays=&format=jws\|es256\|eddsa` |
| Activate / free seat | `PATCH license` `{"License","Code"}` (`Code:null` = uninstall, 204) |
| Public keys | `GET /api/signingkeys.json` |

Headers: `X-API-KEY` (`PUB_` client key), `X-Correlation-Id`,
`Idempotency-Key` on POSTs. Status model:
`Valid · ValidTrial · InvalidTrial · ReceiptExpired · ReceiptUnregistered ·
Expired(file)` — file expiry always wins, then the signed server status,
then the legacy trial/receipt fallback (same precedence as the .NET SDK).

## Behavior parity with the .NET SDK

Beyond the wire contract, the client reproduces the SDK's operational
behavior, each pinned by a mock-transport flow test (`tests/hlm_flow_tests.c`)
that mirrors the concepts of `LicenseManagement.EndUser.Test`:

- **Retry policy** (`ApiHttp`): 3 attempts; transient = 429/408/5xx except
  501/505; `Retry-After` honored; 200 ms exponential backoff capped at 5 s,
  10 s total wait ceiling; 401/403 terminal, never retried.
- **Clock-tamper resistance** (`TimeSyncDiagnostic`): every public call
  resolves ONE trusted evaluation time. Windows port: local clock only if
  w32time is running, NTP-configured, and within 1 h of time.windows.com,
  else SNTP pool.ntp.org — the client then falls back to `GET DateTime`,
  then the local clock. Winding the clock back does not resurrect a lapsed
  trial.
- **Flow semantics**: 201/409 both succeed on POSTs; PATCH 404 recreates the
  license and retries; tampered or expired caches silently refetch; offline
  with a verified-but-expired cache surfaces `Expired` instead of failing;
  uninstall always uses the live hardware id, never the cached file's; the
  refreshed file lands in `ReceiptUnregistered` state after deactivation.

## Scope & roadmap

- [ ] Portable Ed25519 verify (`HLM_ALG_EDDSA` currently needs a custom
      crypto port; server already signs `format=eddsa`)
- [ ] POSIX ports: libcurl `hlm_http`, `/etc/machine-id`-based fingerprint
- [ ] P-256 fast reduction (verification is ~100 ms portable; correctness
      first, speed later — licenses verify once per launch)
- [ ] Offline request/response activation files (air-gapped desktops)
- [x] Clock-tamper trusted-time cascade (w32time / SNTP / GET DateTime) — done
- [ ] CI: build matrix (MSVC/gcc/clang × x64/arm64) + artifact publishing

**Non-goals:** XML-DSig verification (that is what `format=jws` exists to
avoid); private-key operations (this library never signs anything).
