# hymmalm — Rust wrapper

Rust binding for **license-management-core**. All licensing behavior — JWS
verification, status rules, machine fingerprint, REST flow, retry policy,
clock-tamper resistance — lives in the native core; this crate only marshals.
See the repository root README for the architecture.

## Usage

```rust
use hymmalm::{LicenseClient, LicenseClientOptions, LicenseStatus};

let mut client = LicenseClient::new(LicenseClientOptions {
    product_id: "PRD_01KWWPEPM0N070BDAHJ7G09RGV".into(),
    client_api_key: "PUB_...".into(),                    // never a MST_ key
    jwks_json: std::fs::read_to_string("signingkeys.json")?, // GET /api/signingkeys.json
    license_path: Some(dirs_path.join("license.lic")),
    ..Default::default()
})?;

let status = client.check()?;                            // trial bootstrap on first run
if status == LicenseStatus::InvalidTrial {
    client.activate(&receipt_code_from_user)?;
}
```

Offline verification only (no network, e.g. checking a provisioned file):

```rust
let status = hymmalm::verify(&jws_string, &jwks_json, None, None, None)?;
```

Errors are `hymmalm::LicenseError { code, detail }` — `code` is the native
`hlm_err` (e.g. `-7` network failure, `-12` invalid API key, `-13` trial
quota exceeded) and `detail` carries the server's human-readable refusal
reason when it sent one.

## Native core — self-contained build

Unlike the Python/.NET wrappers, this crate **vendors the C core**: the
sources are copied under `csrc/` (maintained by `sync-csrc.sh`; CI fails if
they drift from the canonical `../../src`) and `build.rs` compiles them with
the [`cc`] crate, linking statically. There is no shared library to build,
ship, or locate — a plain `cargo build` produces a self-contained binary,
and the published crates.io tarball carries everything it needs. You only
need a C compiler (cc/clang on Unix, MSVC on Windows; the Windows build
links `winhttp`/`bcrypt`/`ws2_32`/`advapi32` automatically).

On Linux/macOS the HTTP transport `dlopen()`s the system libcurl at runtime
(any distro flavor works); no curl development package is needed at build
time.

After changing the canonical C core, re-run `./sync-csrc.sh` and commit the
refreshed copies — never edit `csrc/` directly.

## Publishing

CI publishes to crates.io automatically on `v*` release tags (the `crates`
job, authenticated by the `CARGO_REGISTRY_TOKEN` secret). `cargo package`
runs on every CI build to prove the standalone tarball compiles. The
integration tests are not packaged (they replay `../../tests/vectors` from
the repo checkout).

## Threading

The native handle must not be used from two threads at once, so
`LicenseClient` is `Send` but **not** `Sync`: move it between threads freely,
or wrap it in a `Mutex` to share it — which is exactly the Tauri pattern
below.

## Using from Tauri

The crate is Tauri-ready as-is (static native core, no runtime files to
bundle). Hold the client in managed state behind a `Mutex` and expose the
operations as commands:

```rust
use std::sync::Mutex;
use hymmalm::{LicenseClient, LicenseClientOptions};

struct Licensing(Mutex<LicenseClient>);

#[tauri::command]
fn license_check(state: tauri::State<Licensing>) -> Result<String, String> {
    let mut client = state.0.lock().unwrap();
    client
        .check()
        .map(|s| format!("{s:?}"))
        .map_err(|e| e.to_string()) // e.detail has the server's refusal reason
}

#[tauri::command]
fn license_activate(receipt: String, state: tauri::State<Licensing>) -> Result<String, String> {
    let mut client = state.0.lock().unwrap();
    client
        .activate(&receipt)
        .map(|s| format!("{s:?}"))
        .map_err(|e| e.to_string())
}

fn main() {
    let client = LicenseClient::new(LicenseClientOptions {
        product_id: "PRD_...".into(),
        client_api_key: "PUB_...".into(),
        jwks_json: include_str!("../signingkeys.json").into(),
        license_path: Some(std::env::temp_dir().join("myapp-license.lic")), // pick a real app-data path
        ..Default::default()
    })
    .expect("licensing options");

    tauri::Builder::default()
        .manage(Licensing(Mutex::new(client)))
        .invoke_handler(tauri::generate_handler![license_check, license_activate])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

(`tauri` is not a dependency of this crate — the snippet goes in your app.)

## Tests

```bash
cd wrappers/rust
cargo test
```

`tests/vectors.rs` replays the same signed vectors as the C suite;
`tests/flow.rs` runs the full client flow (trial → activate → offline cache →
deactivate, plus error classification) against a hand-rolled local mock API in
a single sequential test. The flow test needs libcurl present at runtime (it
is on any normal Linux/macOS install).

[`cc`]: https://crates.io/crates/cc
