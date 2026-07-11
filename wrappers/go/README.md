# hymmalm — Go wrapper for license-management-core

A thin cgo binding over the native `hymmalm` shared library
(`include/hymma/hlm_ffi.h`). All licensing logic — JWS verification, status
rules, machine fingerprinting, the REST client flow, retry policy and
clock-tamper resistance — lives in the native core, so every language wrapper
behaves identically. This package only marshals.

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

## Building and linking

CGO is required. The `#cgo` directives in `hymmalm.go` point at the in-repo
header and build tree:

- headers: `-I${SRCDIR}/../../include`
- library: `-L${SRCDIR}/../../build -lhymmalm -Wl,-rpath,${SRCDIR}/../../build`

so an in-repo `go build`/`go test` works as soon as the native library has
been built (`cmake` → `build/libhymmalm.so`).

**Installed deployments** should override the link flags to point at the
installed library instead, e.g.:

```sh
CGO_CFLAGS="-I/usr/local/include" \
CGO_LDFLAGS="-L/usr/local/lib -lhymmalm" \
go build ./...
```

At run time the dynamic loader must find `libhymmalm.so` (`.dylib` on macOS,
`hymmalm.dll` on Windows) — via the rpath baked in above, `LD_LIBRARY_PATH`,
or a standard library directory.

## Tests

```sh
cd wrappers/go
go vet ./... && go test ./... -v
```

If the rpath does not cover the location `go test` runs the binary from,
prepend `LD_LIBRARY_PATH=$PWD/../../build`.

The tests mirror the Python wrapper's suite: vector-driven verification over
`tests/vectors/*.json`, product/machine binding, machine identity, and the
full check → activate → offline-cache → deactivate flow against an
`httptest` mock of the license API (with `HLM_TIMESYNC=off` and a fixed mock
`GET /api/DateTime` so vector statuses stay deterministic). The dead-URL
tests take a couple of seconds — the native client retries transient
transport failures 3x with 200–600 ms backoff.
