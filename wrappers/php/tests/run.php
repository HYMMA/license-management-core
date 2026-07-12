<?php

/**
 * Test runner: executes each test script in its own PHP process (they set
 * process-level environment variables and load the native library) and
 * exits nonzero if any of them fail.
 *
 *   HYMMALM_LIB=$PWD/../../build/libhymmalm.so php tests/run.php
 */

declare(strict_types=1);

$tests = ['vectors-test.php', 'flow-test.php'];
$failed = [];

foreach ($tests as $test) {
    echo "===== {$test} =====\n";
    passthru(
        escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $test),
        $code
    );
    if ($code !== 0) {
        $failed[] = $test;
    }
    echo "\n";
}

if ($failed === []) {
    echo "ALL TEST SUITES PASSED\n";
    exit(0);
}

echo 'FAILED SUITES: ' . implode(', ', $failed) . "\n";
exit(1);
