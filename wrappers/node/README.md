# hymmalm (Node.js)

Node.js wrapper for **license-management-core**. A thin
[koffi](https://koffi.dev) binding over the native `hymmalm` shared library
(`include/hymma/hlm_ffi.h`) — all licensing logic (JWS verification, status
rules, machine fingerprinting, the REST client flow, retries, clock-tamper
resistance) lives in the native core, so every language wrapper behaves
identically.

## Installing

```bash
npm install hymmalm
```

Published releases bundle the native library for linux-x64/arm64,
macOS arm64/x64 and Windows x64 under `prebuilt/` — nothing else to
install. On other platforms, build the core yourself and see "Locating the
native library" below.

## Usage

```js
const { LicenseClient, LicenseStatus } = require('hymmalm');

const client = new LicenseClient({
  productId: 'PRD_01KWWPEPM0N070BDAHJ7G09RGV',
  clientApiKey: 'PUB_...',                 // never ship a MST_ key
  jwksJson: fs.readFileSync('signingkeys.json', 'utf8'),
  licensePath: path.join(os.homedir(), '.myapp', 'license.lic'),
});

const status = client.check();             // trial bootstrap on first run
if (status === LicenseStatus.InvalidTrial) {
  client.activate(userEnteredReceiptCode); // attach a purchased receipt
}
console.log(client.productName, client.expires);
client.close();
```

Offline helpers (no client needed):

```js
const { verify, machineId, machineName } = require('hymmalm');
const status = verify(jws, jwksJson);      // throws LicenseError if tampered
```

## Locating the native library

The wrapper looks for the shared library in this order:

1. `HYMMALM_LIB` environment variable — the **full path** to the built
   library, e.g. `/path/to/license-management-core/build/libhymmalm.so`
2. `prebuilt/<platform>-<arch>/` inside the package (release bundles)
3. `libhymmalm.so` / `libhymmalm.dylib` / `hymmalm.dll` next to `index.js`
4. the standard system loader search

## Publishing

CI publishes to npm on `v*` release tags (the `npm` job): it arranges each
platform's freshly built library under `prebuilt/`, sets the version from
the tag, and runs `npm publish` authenticated by the `NPM_TOKEN` secret.

## Running the tests

Build the native core first (`cmake` in the repo root produces
`build/libhymmalm.so`), then:

```sh
cd wrappers/node
npm install
HYMMALM_LIB=$PWD/../../build/libhymmalm.so npm test
```

The suite mirrors the Python wrapper's tests: signed-vector compatibility
(`test/vectors.test.js`) and the full trial → activate → offline-cache →
deactivate flow against a local mock of the license API
(`test/flow.test.js`). The dead-URL tests exercise the native retry policy,
so they take a couple of seconds — that's expected.
