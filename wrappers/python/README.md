# hymmalm — Python wrapper

Python (`ctypes`) binding for **license-management-core**. All licensing
behavior — JWS verification, status rules, machine fingerprint, REST flow,
retry policy, clock-tamper resistance — lives in the native `hymmalm`
library; this package only marshals. See the repository root README for the
architecture.

## Usage

```python
from hymmalm import LicenseClient, LicenseStatus

client = LicenseClient(
    product_id="PRD_01KWWPEPM0N070BDAHJ7G09RGV",
    client_api_key="PUB_...",                    # never a MST_ key
    jwks_json=open("signingkeys.json").read(),   # GET /api/signingkeys.json
    license_path="~/.myapp/license.lic",
)

status = client.check()                          # trial bootstrap on first run
if status == LicenseStatus.INVALID_TRIAL:
    client.activate(input("Receipt code: "))
```

Offline verification only (no network, e.g. checking a provisioned file):

```python
import hymmalm
status = hymmalm.verify(jws_string, jwks_json)
```

## Native library

Build the core once (`cmake -S . -B build && cmake --build build` at the
repo root) and either place `libhymmalm.so` / `libhymmalm.dylib` /
`hymmalm.dll` next to the `hymmalm` package, on the loader path, or point
`HYMMALM_LIB` at the full path.

## Tests

```bash
cd wrappers/python
HYMMALM_LIB=$PWD/../../build/libhymmalm.so python -m unittest discover -s tests -v
```

`tests/test_vectors.py` replays the same signed vectors as the C suite;
`tests/test_flow.py` runs the full client flow (trial → activate → offline
cache → deactivate, plus error classification) against a local mock API.
