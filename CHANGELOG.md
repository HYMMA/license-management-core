# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/HYMMA/license-management-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/HYMMA/license-management-core/releases/tag/v0.1.0
