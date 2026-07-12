<?php

/**
 * End-to-end client flow against a local mock of the license API.
 *
 * The mock (tests/mock-router.php, run via `php -S` in a child process)
 * serves the checked-in signed vectors and a fixed `GET DateTime`
 * (2026-07-10T00:00:00Z). HLM_TIMESYNC=off makes the native client resolve
 * its trusted evaluation time from that endpoint, so the expected statuses
 * are deterministic regardless of the real clock — and the server-time
 * fallback of the clock-tamper cascade is exercised on every call.
 *
 * Plain script — no PHPUnit. Exits 1 on any failure.
 */

declare(strict_types=1);

// Must be set BEFORE any native call: the C core reads it via getenv() on
// each call, and putenv() modifies this process's real environment.
putenv('HLM_TIMESYNC=off');

require __DIR__ . '/../src/LicenseClient.php';

use Hymma\Licensing\LicenseClient;
use Hymma\Licensing\LicenseException;
use Hymma\Licensing\LicenseStatus;
use Hymma\Licensing\SignedFormat;

const PRODUCT = 'PRD_01KWWPEPM0N070BDAHJ7G09RGV';
const MACHINE = 'KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG';
const DEAD_BASE = 'http://127.0.0.1:1/api/';

$GLOBALS['pass'] = 0;
$GLOBALS['fail'] = 0;

function check(bool $ok, string $label): void
{
    if ($ok) {
        $GLOBALS['pass']++;
        echo "  ok:   {$label}\n";
    } else {
        $GLOBALS['fail']++;
        echo "  FAIL: {$label}\n";
    }
}

/** @param list<int> $codes acceptable LicenseException codes */
function expectError(callable $fn, array $codes, string $label): ?LicenseException
{
    try {
        $fn();
        check(false, "{$label}: expected LicenseException, none thrown");
    } catch (LicenseException $e) {
        check(
            in_array($e->getCode(), $codes, true),
            "{$label} (got code {$e->getCode()}: {$e->getMessage()})"
        );

        return $e;
    }

    return null;
}

$vec = json_decode(
    file_get_contents(dirname(__DIR__, 3) . '/tests/vectors/vectors.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
$JWKS = json_encode([$vec['RsaJwk']], JSON_THROW_ON_ERROR);

// ---------------------------------------------------------------------- //
// mock server bootstrap (child process: php -S + router)                  //
// ---------------------------------------------------------------------- //

$stateFile = sys_get_temp_dir() . '/hlm-php-mock-' . getmypid() . '.json';

function setState(array $state): void
{
    file_put_contents(
        $GLOBALS['stateFile'],
        json_encode($state, JSON_THROW_ON_ERROR)
    );
}

// Pick a free port by binding to :0, then hand it to php -S.
$probe = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($probe === false) {
    fwrite(STDERR, "cannot allocate a port: {$errstr}\n");
    exit(1);
}
$name = stream_socket_get_name($probe, false);
$port = (int) substr($name, strrpos($name, ':') + 1);
fclose($probe);

setState(['license_case' => 'rs256-trial-valid']);

$env = getenv(); // full current environment (includes HLM_TIMESYNC)
$env['HLM_MOCK_STATE'] = $stateFile;

$proc = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:{$port}", __DIR__ . '/mock-router.php'],
    [
        0 => ['file', '/dev/null', 'r'],
        1 => ['file', '/dev/null', 'w'],
        2 => ['file', '/dev/null', 'w'],
    ],
    $pipes,
    __DIR__,
    $env
);
if ($proc === false) {
    fwrite(STDERR, "cannot start the mock server\n");
    exit(1);
}

// Poll until the server accepts connections.
$up = false;
for ($i = 0; $i < 100; $i++) {
    $s = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
    if ($s !== false) {
        fclose($s);
        $up = true;
        break;
    }
    usleep(100_000);
}
if (!$up) {
    fwrite(STDERR, "mock server did not come up on port {$port}\n");
    proc_terminate($proc);
    proc_close($proc);
    exit(1);
}

$BASE = "http://127.0.0.1:{$port}/api/";
$licPath = __DIR__ . '/flow-test.lic';

function makeClient(?string $base = null, ?string $path = null): LicenseClient
{
    return new LicenseClient(
        baseUrl: $base ?? $GLOBALS['BASE'],
        productId: PRODUCT,
        clientApiKey: 'PUB_test',
        jwksJson: $GLOBALS['JWKS'],
        format: SignedFormat::Rs256,
        machineId: MACHINE,
        machineName: 'SHOP-FLOOR-01',
        licensePath: $path,
    );
}

@unlink($licPath);

try {
    // ------------------------------------------------------------------ //
    // trial -> activate -> offline cache -> deactivate                    //
    // ------------------------------------------------------------------ //
    echo "flow: trial -> activate -> cache -> deactivate\n";
    try {
        $c = makeClient(path: $licPath);
        check($c->check() === LicenseStatus::ValidTrial, 'check() -> ValidTrial');
        check(
            $c->licenseId() === 'LIC_01KWVTRYMCAGWHTCVBYFGNJDA0',
            'licenseId() == LIC_01KWVTRYMCAGWHTCVBYFGNJDA0'
        );
        check($c->productName() === 'CADshift Nesting', 'productName() == "CADshift Nesting"');
        check($c->trialEnd() !== null, 'trialEnd() is not null');

        check(
            $c->activate('RCPT-CODE-1234') === LicenseStatus::Valid,
            'activate("RCPT-CODE-1234") -> Valid'
        );
        check($c->buyerEmail() === 'jane@example.com', 'buyerEmail() == jane@example.com');
        check($c->metadata('seat') === 'floor-1', 'metadata("seat") == "floor-1"');
        check($c->liveMode() === true, 'liveMode() is true');
        check($c->expires() !== null, 'expires() is not null');
        $c->close();
        unset($c);

        // A fresh client on a dead URL must surface the cached license.
        $c = makeClient(DEAD_BASE, $licPath);
        check(
            $c->check() === LicenseStatus::Valid,
            'dead URL + cache: check() -> Valid (offline cache)'
        );
        $c->close();
        unset($c);

        $c = makeClient(path: $licPath);
        check($c->check() === LicenseStatus::Valid, 'live URL + cache: check() -> Valid');
        check(
            $c->deactivate() === LicenseStatus::ReceiptUnregistered,
            'deactivate() -> ReceiptUnregistered'
        );
        $c->close();
        unset($c);
    } catch (\Throwable $e) {
        check(false, 'unexpected exception: ' . $e->getMessage());
    }

    // ------------------------------------------------------------------ //
    // 401 everywhere -> INVALID_API_KEY (-12)                             //
    // ------------------------------------------------------------------ //
    echo "failure: 401 -> INVALID_API_KEY\n";
    setState(['license_case' => 'rs256-trial-valid', 'fail_status' => 401]);
    $c = makeClient();
    expectError(
        fn () => $c->check(),
        [LicenseException::INVALID_API_KEY],
        'check() with 401 -> code -12'
    );
    $c->close();
    unset($c);

    // ------------------------------------------------------------------ //
    // 402 trial_quota -> TRIAL_QUOTA_EXCEEDED (-13) with detail           //
    // ------------------------------------------------------------------ //
    echo "failure: 402 trial_quota -> TRIAL_QUOTA_EXCEEDED\n";
    setState([
        'license_case' => 'rs256-trial-valid',
        'fail_status' => 402,
        'fail_body' => json_encode([
            'error' => 'trial_quota',
            'detail' => 'Active-trial quota exhausted.',
        ]),
    ]);
    $c = makeClient();
    $e = expectError(
        fn () => $c->check(),
        [LicenseException::TRIAL_QUOTA_EXCEEDED],
        'check() with 402 trial_quota -> code -13'
    );
    check(
        $e !== null && str_contains($e->detail, 'quota'),
        'exception detail contains "quota"'
    );
    $c->close();
    unset($c);

    // ------------------------------------------------------------------ //
    // dead URL, no cache -> NETWORK_FAILURE (-7)                          //
    // ------------------------------------------------------------------ //
    echo "failure: dead URL without cache -> NETWORK_FAILURE\n";
    setState(['license_case' => 'rs256-trial-valid']);
    $c = makeClient(DEAD_BASE);
    expectError(
        fn () => $c->check(),
        [LicenseException::NETWORK_FAILURE],
        'check() against dead URL -> code -7'
    );
    $c->close();
    unset($c);
} finally {
    proc_terminate($proc);
    proc_close($proc);
    @unlink($stateFile);
    @unlink($licPath);
}

printf(
    "flow-test: %d passed, %d failed\n",
    $GLOBALS['pass'],
    $GLOBALS['fail']
);
exit($GLOBALS['fail'] === 0 ? 0 : 1);
