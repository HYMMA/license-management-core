# hymma-licensing — Java wrapper for license-management-core

Thin [java.lang.foreign (FFM)](https://openjdk.org/jeps/442) binding over the
native `hymmalm` shared library (`include/hymma/hlm_ffi.h`). All licensing
logic — JWS verification, status rules, machine fingerprinting, the REST
client flow, retry policy and clock-tamper resistance — lives in the native
core, so every language wrapper behaves identically. This package only
marshals.

## Requirements

- **JDK 21**: the FFM API is a *preview* feature — compile with
  `javac --release 21 --enable-preview` and run with `java --enable-preview`.
- **JDK 22+**: the FFM API is final; the `--enable-preview` flags can be
  dropped (the code compiles unchanged).
- The native library, built with CMake from the repo root
  (`build/libhymmalm.so`). It is located via the **`HYMMALM_LIB`**
  environment variable (full path), falling back to the standard loader
  search for `System.mapLibraryName("hymmalm")` (`libhymmalm.so` /
  `libhymmalm.dylib` / `hymmalm.dll` on `java.library.path` / `LD_LIBRARY_PATH`).

## Usage

```java
import com.hymma.licensing.*;

try (var client = new LicenseClient(LicenseClientOptions.builder()
        .productId("PRD_01KWWPEPM0N070BDAHJ7G09RGV")
        .clientApiKey("PUB_...")                       // never ship a MST_ key
        .jwksJson(Files.readString(Path.of("signingkeys.json")))
        .licensePath(home.resolve(".myapp/license.lic").toString())
        .build())) {

    LicenseStatus status = client.check();             // trial bootstrap on first run
    if (status == LicenseStatus.INVALID_TRIAL) {
        client.activate(userEnteredReceiptCode);       // attach a purchased receipt
    }

    System.out.println(client.productName() + " -> " + client.status()
            + ", expires " + client.expires().orElse(null));
} catch (LicenseException e) {
    // e.code() is the classified native error (-7 network, -12 bad key, ...);
    // e.detail() carries the server's human-readable refusal reason.
    System.err.println(e.getMessage());
}
```

Offline verification and machine identity, without a client:

```java
LicenseStatus s = LicenseClient.verify(jws, jwksJson,
        expectedProductId, expectedMachineId, Instant.now());
String fingerprint = LicenseClient.machineId();   // 52-char Crockford Base32
```

## Tests

No Maven/Gradle needed — a plain script compiles the sources plus a tiny
dependency-free test runner and executes the vector and flow suites against
the checked-in signed vectors (`tests/vectors/*.json`) and a local mock of
the license API:

```bash
./run-tests.sh
```

The script exports `HLM_TIMESYNC=off` (pins the native trusted time to the
mock server's `GET /api/DateTime`, making statuses deterministic — Java
cannot set environment variables for its own process, so the wrapper cannot
do this itself) and points `HYMMALM_LIB` at `../../build/libhymmalm.so` by
default. Expect `--enable-preview` warnings from javac on JDK 21; they are
harmless.

The `pom.xml` is provided for consumers who build with Maven; it is not used
by `run-tests.sh`.
