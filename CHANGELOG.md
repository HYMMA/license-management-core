# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-15

### Added

- **Say what failed when the server is unreachable.** A transport failure is
  still `HLM_E_HTTP`, but the client now records why — `hlm_net_failure`:
  `NameResolution` (DNS), `SecureConnection` (TLS), `Proxy`, `Timeout`,
  `Connection`, `Unknown` — in `hlm_client.last_net_failure`
  (`hlm_ffi_last_network_failure`), and puts an end-user message that names
  the host to allow in `last_error` (`hlm_ffi_last_error_detail`), worded as
  the .NET SDK 3.5.0 words it. Every online action used to read "network
  failure", which sent an App Store reviewer whose company DNS refused to
  resolve the server (Windows 11004, `WSANO_DATA`) to check an internet
  connection that was fine. The cause stays visible when `check()` falls
  back to the cached file. Transports report the cause through the new
  `hlm_http_response.failure`; `hlm_net_failure_from_winhttp` /
  `hlm_net_failure_from_curl` map WinHTTP/Winsock errors and CURLcodes, and
  `hlm_net_message` formats the message. A proxy's 407 is classified as
  `Proxy` and not retried.
- **Install a license file by hand** (`hlm_license_import`,
  `hlm_client_import`, `hlm_ffi_import_license`,
  `hlm_ffi_import_license_file`): for computers that cannot reach the
  server, the customer downloads their signed license from the vendor's
  portal (or receives it by email) and the app installs it. The file is
  verified exactly as the offline cache is — vendor signature, product, this
  computer — BEFORE it replaces anything, so a wrong or tampered file never
  displaces a working one. Outcomes (`hlm_import_result`): `Installed`,
  `NotALicenseFile`, `NoPublicKey`, `SignatureInvalid`, `WrongProduct`,
  `WrongComputer`, `WriteFailed`, each with an end-user message
  (`hlm_import_message`). Never touches the network.
- `hlm_ffi_license_path` exposes the license cache file a client reads and
  writes, so a host UI can show it.
- `hlm_license_check_machine`: `hlm_license_check` binding to this machine
  under identity v2 or the legacy v1 id.
- All seven wrappers (.NET, Python, Rust, Go, Java, Node, PHP) expose the
  network failure cause (on the client and on the error), license-file
  import (`ImportLicense` / `ImportLicenseFile` returning outcome + message)
  and the license path.

### Changed

- **WinHTTP uses the system proxy like a browser, before Windows 8.1 too.**
  The session already asked for `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`
  (WPAD/PAC/Internet Options); on Windows older than 8.1, which rejects it,
  it now falls back to `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY` instead of
  failing every request. A proxy's Negotiate/NTLM 407 challenge is answered
  once with the signed-in user's Windows credentials (autologon policy LOW
  on that request only, after the proxy asked) — an authenticating company
  proxy used to fail the license check while the browser worked.
- `HLM_MAX_ERROR_DETAIL` is 512 (was 256) so a network message naming the
  host twice is never truncated; `hlm_client` grows accordingly — rebuild
  code that embeds the struct.

### Fixed

- **The offline load accepts a file bound to this machine's legacy (v1) id**
  when `machine_id_legacy` is configured, as the .NET SDK's
  `ComputerIdValidatorHandler` does. A file issued before the server
  re-keyed the machine to identity v2 was refused offline as another
  computer's and re-fetched — impossible without a network.

## [0.1.5] - 2026-09-25

### Fixed

- **Machine identity v2** (`hlm_machine_id_win_v2` / `hlm_ffi_machine_id_v2`):
  fingerprint of the Windows `MachineGuid` (unique per Windows install).
  The v1 sources collide across unrelated machines — `ProcessorId` is shared
  by every CPU of the same model and OEM baseboards often report placeholder
  serials — which handed one customer's expired-trial row to another customer's
  brand-new install. `hlm_client_cfg` gains `machine_id_legacy`: when set, the
  client sends it as `LegacyMacAddress` (POST body and GET query, along with
  `name`) so the server can re-key the machine's existing row to the v2 id
  instead of minting a fresh trial. `hlm_ffi_create` with `machine_id == NULL`
  now derives v2 + v1-legacy automatically (v1 alone when no `MachineGuid`).
  POSIX ids were already install-unique and are unchanged. Upgrading is
  seamless for existing installs: the server re-keys their machine rows.

## [0.1.2] - [0.1.4] - 2026-07-13

Released without separate notes; together they added:

### Added

- Maven Central publishing on `v*` tags (`net.hymma:hymmalm`): release jars
  bundle all five platform libraries under `/native/` and the Java loader
  extracts the right one at runtime — same batteries-included install as
  pip/npm. Sources + javadoc attached, artifacts GPG-signed, uploaded via
  the Central Portal (`CENTRAL_USERNAME`/`CENTRAL_PASSWORD`,
  `GPG_PRIVATE_KEY`/`GPG_PASSPHRASE`).

- **Portable Ed25519 (EdDSA) verification** in the built-in crypto backend —
  dependency-free C99 (16-bit-limb field arithmetic, no `__int128`, MSVC and
  32-bit MCU friendly), with RFC 8032 canonicality checks (rejects S ≥ L
  malleability and off-curve points). `format=eddsa` licenses now verify
  everywhere without a custom crypto port. New SHA-512 primitive.
- **POSIX ports** (Linux/macOS): libcurl HTTP transport (dlopen'd at runtime —
  no link-time dependency), `/etc/machine-id`-based fingerprint on Linux and
  `gethostuuid()` on macOS (`hlm_machine_id_posix`), `gethostname()` machine
  name, `nanosleep` retry backoff, and an SNTP trusted-time cascade
  (`pool.ntp.org`, `HLM_NTP_HOST` override, `HLM_TIMESYNC=off` opt-out).
  `hlm_ffi_create` now works out of the box on non-Windows platforms.
- **Language wrappers with test suites**: Python (`ctypes`), Node.js
  (`koffi`), Go (`cgo`), Java (FFM / `java.lang.foreign`), PHP (`FFI`) and
  Rust (self-contained crate that also serves Tauri apps) under `wrappers/`.
  Every wrapper replays the signed JWS vectors and runs the full client flow
  (trial bootstrap → activate → offline cache → deactivate, plus error
  classification) against a local mock API.
- EdDSA test vectors (`tests/vectors/vectors-eddsa.json`, generated by
  `tools/eddsa-vectorgen`); `hlm_tests` accepts multiple vector files.
- CI: build matrix extended to gcc/clang/MSVC across linux-x64, linux-arm64,
  windows-x64, macos-x64 and macos-arm64, with per-wrapper test jobs; NuGet
  package now bundles linux-arm64 and osx-x64 native runtimes too.
- Publishing: the Go module and Rust crate are self-contained (C core
  vendored via `sync-csrc.sh`, drift-checked in CI). Go releases via
  `wrappers/go/vX.Y.Z` tags (no registry); the `hymmalm` crate publishes to
  crates.io automatically on `v*` tags (`CARGO_REGISTRY_TOKEN`); PyPI
  publishing on `v*` tags builds one binary wheel per platform (native
  library bundled, linux wheels vetted/retagged by auditwheel) plus a pure
  sdist (`PYPI_API_TOKEN`); npm publishing on `v*` tags bundles all five
  platform libraries under `prebuilt/` in one package (`NPM_TOKEN`).

## [0.1.1] - 2026-07-10

### Added

- Server refusals are classified into dedicated errors (HLM_E_TRIAL_QUOTA,
  HLM_E_PAID_FORMAT_REQUIRED, HLM_E_PLAN_LIMIT) and the server's
  human-readable detail is captured (hlm_ffi_last_error_detail); the .NET
  wrapper surfaces both via LicenseError / LicenseException.Detail.
- NuGet publishing of LicenseManagement.Core (win-x64 / linux-x64 /
  osx-arm64 native runtimes bundled) on release tags.

### Changed

- .NET wrapper renamed Hymma.Lm.Core -> LicenseManagement.Core to match the
  LicenseManagement.* package family; repo renamed to license-management-core.
- Release assets renamed to licMngm-core-<version>-<os>-<arch>.zip.

## [0.1.0] - 2026-07-10

Initial release.

### Added

- Portable C99 core: compact JWS verification (RS256, ES256) with
  dependency-free RSA PKCS#1 v1.5 and ECDSA P-256 verifiers; JWK key parsing;
  license payload model and the License-Management.com status state machine.
- Windows CNG crypto backend (cross-checked against the portable verifiers in
  every test run).
- REST client flow matching the .NET LicenseManagement.EndUser SDK: register
  computer, obtain / activate / deactivate licenses, offline cache, ApiHttp
  retry policy (3 attempts, Retry-After, exponential backoff, 401/403
  terminal), TimeSyncDiagnostic-style trusted-time cascade
  (w32time → SNTP → GET DateTime → local clock).
- Machine fingerprint byte-identical to the .NET SDK's DeviceId pipeline
  (SMBIOS baseboard serial + CPUID → SHA-256 → Crockford Base32).
- Ports: WinHTTP transport, file storage, system clock, Windows sleep; all
  replaceable for embedded targets. `HLM_BN_MAX_LIMBS` build knob for
  ES256-only MCU builds.
- Flat FFI ABI (`hlm_ffi.h`) and the .NET reference wrapper
  (`LicenseManagement.Core`, netstandard2.0).
- Test suites: FIPS/RFC unit vectors, .NET-cross-signed JWS vectors, and a
  scripted mock-transport suite mirroring the .NET SDK's test concepts.

### Known limitations

- EdDSA (Ed25519) verification requires a custom crypto port (portable
  implementation on the roadmap).
- Built-in HTTP/fingerprint ports are Windows-only; POSIX ports planned.
- P-256 verification favors reviewability over speed (~100 ms desktop).

[Unreleased]: https://github.com/HYMMA/license-management-core/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/HYMMA/license-management-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/HYMMA/license-management-core/releases/tag/v0.1.0
