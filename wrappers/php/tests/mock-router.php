<?php

/**
 * Router script for `php -S 127.0.0.1:<port> tests/mock-router.php` — a
 * local mock of the license API used by tests/flow-test.php.
 *
 * Each request runs as a fresh execution of this script, so mutable state
 * (which signed license case to serve, or a forced failure mode) lives in a
 * JSON file whose path arrives via the HLM_MOCK_STATE environment variable:
 *
 *   { "license_case": "rs256-trial-valid",
 *     "fail_status": 401,            // optional: fail all GET/POST with this
 *     "fail_body": "{...}" }         // optional body for the failure
 *
 * Endpoints (the native client requests base_url + path):
 *   GET  /api/DateTime  -> 200 "2026-07-10T00:00:00Z"   (quoted JSON string)
 *   GET  /api/computer  -> 200 {"id":"PC_01KWVTRYM7AXBT1V56M2N3E3AB"}
 *   GET  /api/license   -> 200 raw JWS of the current license_case
 *   POST /api/computer, /api/license -> 201 {}
 *   PATCH /api/license  -> 204; body.Code non-null selects rs256-paid-valid,
 *                          Code null selects rs256-receipt-unregistered
 */

declare(strict_types=1);

$stateFile = getenv('HLM_MOCK_STATE')
    ?: sys_get_temp_dir() . '/hlm-php-mock-state.json';

$raw = @file_get_contents($stateFile);
$state = $raw !== false ? json_decode($raw, true) : null;
if (!is_array($state)) {
    $state = [];
}
$state += ['license_case' => 'rs256-trial-valid'];

$vec = json_decode(
    file_get_contents(dirname(__DIR__, 3) . '/tests/vectors/vectors.json'),
    true
);
$cases = [];
foreach ($vec['Cases'] as $c) {
    $cases[$c['Name']] = $c['Jws'];
}

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

function respond(int $code, string $body = ''): bool
{
    http_response_code($code);
    header('Content-Length: ' . strlen($body));
    echo $body;

    return true; // tell php -S the request was handled
}

if (($method === 'GET' || $method === 'POST') && !empty($state['fail_status'])) {
    return respond((int) $state['fail_status'], (string) ($state['fail_body'] ?? '{}'));
}

if ($method === 'GET') {
    if (str_starts_with($path, '/api/DateTime')) {
        return respond(200, '"2026-07-10T00:00:00Z"');
    }
    if (str_starts_with($path, '/api/computer')) {
        return respond(200, '{"id":"PC_01KWVTRYM7AXBT1V56M2N3E3AB"}');
    }
    if (str_starts_with($path, '/api/license')) {
        return respond(200, $cases[$state['license_case']]);
    }

    return respond(404, '{}');
}

if ($method === 'POST') {
    file_get_contents('php://input'); // drain the body
    return respond(201, '{}');
}

if ($method === 'PATCH') {
    $req = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];
    $state['license_case'] =
        (array_key_exists('Code', $req) && $req['Code'] !== null)
            ? 'rs256-paid-valid'
            : 'rs256-receipt-unregistered';
    file_put_contents($stateFile, json_encode($state));

    return respond(204);
}

return respond(404, '{}');
