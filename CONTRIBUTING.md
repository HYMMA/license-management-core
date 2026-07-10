# Contributing

Thanks for your interest in hymma-lm-core.

## Ground rules

- **C99, no dependencies, no heap in the core.** Anything platform-specific
  goes behind a port (`hlm_crypto`, `hlm_http`, `hlm_storage`, `hlm_clock`,
  device identity). If your change needs an OS call in `src/core/`, it needs
  a different design.
- **The wire/file contract is pinned by tests.** `tools/vectorgen` contains a
  byte-for-byte copy of the license server's JWS builder; if your change
  affects verification, regenerate `tests/vectors/vectors.json` and explain
  why in the PR.
- **Behavior parity with the .NET SDK matters.** The client flow
  (`hlm_client.c`) mirrors LicenseManagement.EndUser — retry policy, status
  rules, clock-tamper cascade. Divergence is a bug unless documented.

## Developing

```bash
cmake -S . -B build
cmake --build build
build/hlm_tests tests/vectors/vectors.json
build/hlm_flow_tests tests/vectors/vectors.json
```

Regenerating vectors (needs the .NET SDK):

```bash
cd tools/vectorgen && dotnet run -c Release -- ../../tests/vectors/vectors.json
```

## Pull requests

- One logical change per PR, with tests. Bug fixes need a failing test first.
- Match the existing style (4-space indent, `hlm_` prefix, no C++ in the core).
- CI must be green on Windows, Linux and macOS.

## Security issues

Never open a public issue — see [SECURITY.md](SECURITY.md).
