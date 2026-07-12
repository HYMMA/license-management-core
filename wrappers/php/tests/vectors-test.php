<?php

/**
 * Vector-driven compatibility tests: the wrapper must verify exactly what
 * the license server signs (tests/vectors/*.json) and reject tampered
 * tokens, matching the C test suite case for case.
 *
 * Plain script — no PHPUnit. Exits 1 on any failure.
 */

declare(strict_types=1);

require __DIR__ . '/../src/LicenseClient.php';

use Hymma\Licensing\LicenseClient;
use Hymma\Licensing\LicenseException;
use Hymma\Licensing\LicenseStatus;

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

function loadVectors(string $name): array
{
    $repo = dirname(__DIR__, 3);
    $raw = file_get_contents($repo . '/tests/vectors/' . $name);
    if ($raw === false) {
        fwrite(STDERR, "cannot read vector file {$name}\n");
        exit(1);
    }

    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
}

function jwksOf(array $vec): string
{
    $keys = [];
    foreach (['RsaJwk', 'EcJwk', 'EdJwk'] as $k) {
        if (isset($vec[$k])) {
            $keys[] = $vec[$k];
        }
    }

    return json_encode($keys, JSON_THROW_ON_ERROR);
}

function parseNow(array $case): ?\DateTimeImmutable
{
    if (empty($case['NowUtc'])) {
        return null;
    }

    return new \DateTimeImmutable($case['NowUtc']);
}

function statusByName(string $name): LicenseStatus
{
    /** @var LicenseStatus */
    return constant(LicenseStatus::class . '::' . $name);
}

// ---------------------------------------------------------------------- //
// all cases from both vector files                                        //
// ---------------------------------------------------------------------- //

foreach (['vectors.json', 'vectors-eddsa.json'] as $fname) {
    echo "{$fname}:\n";
    $vec = loadVectors($fname);
    $jwks = jwksOf($vec);
    foreach ($vec['Cases'] as $case) {
        $name = $case['Name'];
        $now = parseNow($case);
        if (!empty($case['Valid'])) {
            try {
                $status = LicenseClient::verify($case['Jws'], $jwks, null, null, $now);
                if (isset($case['ExpectedStatus'])) {
                    $expected = statusByName($case['ExpectedStatus']);
                    check(
                        $status === $expected,
                        "{$name}: status {$status->name} == {$expected->name}"
                    );
                } else {
                    check(true, "{$name}: verified");
                }
            } catch (LicenseException $e) {
                check(false, "{$name}: unexpected error {$e->getMessage()}");
            }
        } else {
            try {
                LicenseClient::verify($case['Jws'], $jwks, null, null, $now);
                check(false, "{$name}: expected rejection, got success");
            } catch (LicenseException $e) {
                check(
                    in_array($e->getCode(), [
                        LicenseException::SIGNATURE_INVALID,
                        LicenseException::MALFORMED_INPUT,
                    ], true),
                    "{$name}: rejected with code {$e->getCode()}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------- //
// product and machine binding                                             //
// ---------------------------------------------------------------------- //

echo "binding:\n";
$vec = loadVectors('vectors.json');
$jwks = jwksOf($vec);
$case = null;
foreach ($vec['Cases'] as $c) {
    if ($c['Name'] === 'rs256-trial-valid') {
        $case = $c;
        break;
    }
}
$now = parseNow($case);
$product = 'PRD_01KWWPEPM0N070BDAHJ7G09RGV';
$machine = 'KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG';

try {
    $status = LicenseClient::verify($case['Jws'], $jwks, $product, $machine, $now);
    check($status === LicenseStatus::ValidTrial, 'matching product+machine -> ValidTrial');
} catch (LicenseException $e) {
    check(false, 'matching product+machine: unexpected error ' . $e->getMessage());
}

try {
    LicenseClient::verify($case['Jws'], $jwks, 'PRD_SOMETHINGELSE', $machine, $now);
    check(false, 'wrong product: expected rejection, got success');
} catch (LicenseException $e) {
    check(
        $e->getCode() === LicenseException::PRODUCT_MISMATCH,
        "wrong product -> PRODUCT_MISMATCH (got {$e->getCode()})"
    );
}

try {
    LicenseClient::verify($case['Jws'], $jwks, $product, 'WRONGMACHINE', $now);
    check(false, 'wrong machine: expected rejection, got success');
} catch (LicenseException $e) {
    check(
        $e->getCode() === LicenseException::COMPUTER_MISMATCH,
        "wrong machine -> COMPUTER_MISMATCH (got {$e->getCode()})"
    );
}

// ---------------------------------------------------------------------- //
// machine identity + error names                                          //
// ---------------------------------------------------------------------- //

echo "machine identity:\n";
check(strlen(LicenseClient::machineId()) === 52, 'machineId() is 52 chars');
check(LicenseClient::machineName() !== '', 'machineName() is non-empty');

$err = new LicenseException(LicenseException::SIGNATURE_INVALID);
check(
    str_contains($err->getMessage(), 'signature'),
    'error message for -4 mentions "signature"'
);

printf(
    "vectors-test: %d passed, %d failed\n",
    $GLOBALS['pass'],
    $GLOBALS['fail']
);
exit($GLOBALS['fail'] === 0 ? 0 : 1);
