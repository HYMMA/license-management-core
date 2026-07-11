# hymmalm — Go wrapper for license-management-core

A thin cgo binding over the native core's flat ABI
(`include/hymma/hlm_ffi.h`). All licensing logic — JWS verification, status
rules, machine fingerprinting, the REST client flow, retry policy and
clock-tamper resistance — lives in the native core, so every language wrapper
behaves identically. This package only marshals.

The C core is **vendored into the module** (flat `hlm_*.c` copies kept in
sync by `sync-csrc.sh`; CI fails on drift) and compiled by cgo, so the
module is fully self-contained:

```sh
go get github.com/HYMMA/license-management-core/wrappers/go@latest
```

needs nothing but a C toolchain — no prebuilt library, no CMake step.

## Usage

```go
import "github.com/HYMMA/license-management-core/wrappers/go" // package hymmalm

client, err := hymmalm.New(hymmalm.Options{
    ProductID:    "PRD_01KWWPEPM0N070BDAHJ7G09RGV",
    ClientAPIKey: "PUB_...",            // never a MST_ key
    JwksJSON:     jwks,                 // from /api/signingkeys.json
    LicensePath:  "/home/me/.myapp/license.lic", // offline cache
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

status, err := client.Check() // trial bootstrap on first run
if err != nil {
    var lerr *hymmalm.Error
    if errors.As(err, &lerr) {
        log.Printf("licensing refused: code=%d detail=%s", lerr.Code, lerr.Detail)
    }
}
if status == hymmalm.StatusInvalidTrial {
    status, err = client.Activate(userEnteredReceiptCode)
}
```

Package-level helpers: `hymmalm.MachineID()`, `hymmalm.MachineName()`, and the
offline one-shot `hymmalm.Verify(jws, jwksJSON, expectedProductID,
expectedMachineID, now)` (pass the zero `time.Time` for the system clock).

One `*Client` per goroutine, or serialize calls yourself — same rule as the
native handle it wraps.

## Building

CGO is required (`CGO_ENABLED=1` plus gcc/clang; on Windows, mingw-w64 —
the vendored Windows ports link `winhttp`/`bcrypt`/`ws2_32`/`advapi32`
automatically). There is nothing else to install: cgo compiles the vendored
`hlm_*.c` sources statically into your binary. On Linux/macOS the HTTP port
dlopen()s the system libcurl at run time.

After changing the canonical C core (`../../src`, `../../include`), re-run
`./sync-csrc.sh` and commit the refreshed copies — never edit the copies
directly.

## Releasing

Go has no registry; a release is a git tag on this public repo using the
submodule-prefixed form, e.g. `wrappers/go/v0.1.1`. proxy.golang.org picks
it up on first request.

## Tests

```sh
cd wrappers/go
go vet ./... && go test ./... -v
```

The tests mirror the Python wrapper's suite: vector-driven verification over
`tests/vectors/*.json`, product/machine binding, machine identity, and the
full check → activate → offline-cache → deactivate flow against an
`httptest` mock of the license API (with `HLM_TIMESYNC=off` and a fixed mock
`GET /api/DateTime` so vector statuses stay deterministic). The dead-URL
tests take a couple of seconds — the native client retries transient
transport failures 3x with 200–600 ms backoff.
