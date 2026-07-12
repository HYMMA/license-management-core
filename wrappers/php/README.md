# hymma/licensing — PHP wrapper for license-management-core

Thin [FFI](https://www.php.net/manual/en/book.ffi.php) binding over the
native `hymmalm` shared library (`include/hymma/hlm_ffi.h`). All licensing
logic — JWS verification, status rules, machine fingerprinting, the REST
client flow, retry policy and clock-tamper resistance — lives in the native
core, so every language wrapper behaves identically. This package only
marshals.

Requires PHP >= 8.1 with `ext-ffi`, and the built native library
(`libhymmalm.so` / `libhymmalm.dylib` / `hymmalm.dll`).

## Install

With composer, add the package and use the PSR-4 autoloader. Without
composer, a single require is enough (it pulls in the enums, the exception
and the FFI binding):

```php
require 'src/LicenseClient.php';
```

## Locating the native library

The library is loaded once (cached statically) from, in order:

1. the `HYMMALM_LIB` environment variable (full path to the shared library),
2. a copy of `libhymmalm.so` / `libhymmalm.dylib` / `hymmalm.dll` placed
   next to `src/LicenseClient.php`,
3. the standard dynamic-loader search path.

## Usage

```php
use Hymma\Licensing\LicenseClient;
use Hymma\Licensing\LicenseException;
use Hymma\Licensing\LicenseStatus;

$client = new LicenseClient(
    productId: 'PRD_01KWWPEPM0N070BDAHJ7G09RGV',
    clientApiKey: 'PUB_...',                        // never a MST_ key
    jwksJson: file_get_contents('signingkeys.json'), // vendor public JWKS
    licensePath: '/home/me/.myapp/license.lic',      // offline cache (optional)
);

try {
    $status = $client->check();                      // trial bootstrap on first run
    if ($status === LicenseStatus::InvalidTrial) {
        $client->activate($userEnteredReceiptCode);  // -> LicenseStatus::Valid
    }
    echo $client->productName(), ' licensed to ', $client->buyerEmail(), "\n";
    echo 'expires: ', $client->expires()?->format(DATE_ATOM) ?? 'never', "\n";
} catch (LicenseException $e) {
    // $e->getCode() is the native error code (LicenseException::NETWORK_FAILURE, ...)
    // $e->detail carries the server's human-readable refusal reason, if any
    echo 'licensing error: ', $e->getMessage(), "\n";
}
```

The constructor also accepts a plain options array with the same keys:
`new LicenseClient(['productId' => ..., 'clientApiKey' => ..., 'jwksJson' => ...])`.

Stateless helpers:

```php
LicenseClient::machineId();     // 52-char hardware fingerprint
LicenseClient::machineName();   // this computer's name
LicenseClient::verify($jws, $jwksJson, $productId, $machineId, $now); // offline one-shot
```

## Running the tests

Plain PHP scripts, no PHPUnit. From `wrappers/php/`:

```bash
HYMMALM_LIB=$PWD/../../build/libhymmalm.so php tests/run.php
```

- `tests/vectors-test.php` — verifies every signed vector in
  `tests/vectors/*.json` (and rejects the tampered ones), plus
  product/machine binding and machine identity.
- `tests/flow-test.php` — full check/activate/offline-cache/deactivate flow
  and the 401 / 402 / network-failure error paths against a local mock of
  the license API (`tests/mock-router.php`, run with `php -S` in a child
  process). The network-failure cases exercise the native 3x retry with
  backoff, so this suite takes a few seconds.
