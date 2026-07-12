'use strict';

/* End-to-end client flow against a local mock of the license API.
 *
 * The mock serves the checked-in signed vectors and a fixed `GET DateTime`
 * (2026-07-10T00:00:00Z). HLM_TIMESYNC=off makes the native client resolve
 * its trusted evaluation time from that endpoint, so the expected statuses
 * are deterministic regardless of the real clock — and the server-time
 * fallback of the clock-tamper cascade is exercised on every call.
 *
 * The native client's HTTP calls are synchronous and block Node's event
 * loop, so the mock server cannot live on the main thread (it would
 * deadlock). This file therefore re-runs itself as a worker thread that
 * hosts the node:http mock, while the main thread runs the tests. */

process.env.HLM_TIMESYNC = 'off'; // before anything touches the native lib

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { Worker, isMainThread, parentPort } = require('node:worker_threads');

const REPO = path.resolve(__dirname, '..', '..', '..');
const VEC = JSON.parse(fs.readFileSync(
  path.join(REPO, 'tests', 'vectors', 'vectors.json'), 'utf8'));
const CASES = Object.fromEntries(VEC.Cases.map((c) => [c.Name, c.Jws]));

/* ---------------------------------------------------------------------- */
/* worker thread: the mock license API                                     */
/* ---------------------------------------------------------------------- */

if (!isMainThread) {
  const state = {
    licenseCase: 'rs256-trial-valid',
    failStatus: 0,
    failBody: '{}',
  };

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      const send = (code, text = '') => {
        res.writeHead(code, { 'Content-Length': Buffer.byteLength(text) });
        res.end(text);
      };
      if (req.method === 'PATCH') {
        const parsed = JSON.parse(body || '{}');
        state.licenseCase = parsed.Code != null
          ? 'rs256-paid-valid'
          : 'rs256-receipt-unregistered';
        return send(204);
      }
      if (state.failStatus) return send(state.failStatus, state.failBody);
      if (req.method === 'GET') {
        if (req.url.startsWith('/api/DateTime')) {
          return send(200, '"2026-07-10T00:00:00Z"');
        }
        if (req.url.startsWith('/api/computer')) {
          return send(200, '{"id":"PC_01KWVTRYM7AXBT1V56M2N3E3AB"}');
        }
        if (req.url.startsWith('/api/license')) {
          return send(200, CASES[state.licenseCase]);
        }
        return send(404, '{}');
      }
      if (req.method === 'POST') return send(201, '{}');
      return send(404, '{}');
    });
  });

  parentPort.on('message', (msg) => {
    if (msg.type === 'set') {
      Object.assign(state, msg.state);
      parentPort.postMessage({ type: 'ack', id: msg.id });
    }
  });

  server.listen(0, '127.0.0.1', () => {
    parentPort.postMessage({ type: 'listening', port: server.address().port });
  });

  return; // worker hosts the server only; no tests below
}

/* ---------------------------------------------------------------------- */
/* main thread: the tests                                                  */
/* ---------------------------------------------------------------------- */

const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');

const {
  LicenseClient, LicenseError, LicenseErrorCode, LicenseStatus, SignedFormat,
} = require('../index.js');

const PRODUCT = 'PRD_01KWWPEPM0N070BDAHJ7G09RGV';
const MACHINE = 'KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG';
const JWKS = JSON.stringify([VEC.RsaJwk]);

let worker;
let base;
let tmpDir;
let nextMsgId = 1;

function setState(state) {
  return new Promise((resolve) => {
    const id = nextMsgId++;
    const onMessage = (msg) => {
      if (msg.type === 'ack' && msg.id === id) {
        worker.off('message', onMessage);
        resolve();
      }
    };
    worker.on('message', onMessage);
    worker.postMessage({ type: 'set', id, state });
  });
}

test.before(async () => {
  worker = new Worker(__filename, { env: process.env });
  const port = await new Promise((resolve, reject) => {
    worker.once('message', (msg) => resolve(msg.port));
    worker.once('error', reject);
  });
  base = `http://127.0.0.1:${port}/api/`;
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hymmalm-flow-'));
});

test.after(async () => {
  await worker.terminate();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test.beforeEach(() => setState({
  licenseCase: 'rs256-trial-valid',
  failStatus: 0,
  failBody: '{}',
}));

function client({ baseUrl = null, licensePath = null } = {}) {
  return new LicenseClient({
    productId: PRODUCT,
    clientApiKey: 'PUB_test',
    jwksJson: JWKS,
    baseUrl: baseUrl || base,
    format: SignedFormat.RS256,
    machineId: MACHINE,
    machineName: 'SHOP-FLOOR-01',
    licensePath,
  });
}

test('trial -> activate -> offline cache -> deactivate', () => {
  const licPath = path.join(tmpDir, 'flow-test.lic');
  if (fs.existsSync(licPath)) fs.rmSync(licPath);

  let c = client({ licensePath: licPath });
  try {
    assert.strictEqual(c.check(), LicenseStatus.ValidTrial);
    assert.strictEqual(c.licenseId, 'LIC_01KWVTRYMCAGWHTCVBYFGNJDA0');
    assert.strictEqual(c.productName, 'CADshift Nesting');
    assert.notStrictEqual(c.trialEnd, null);

    assert.strictEqual(c.activate('RCPT-CODE-1234'), LicenseStatus.Valid);
    assert.strictEqual(c.buyerEmail, 'jane@example.com');
    assert.strictEqual(c.metadata('seat'), 'floor-1');
    assert.strictEqual(c.liveMode, true);
    assert.notStrictEqual(c.expires, null);
  } finally {
    c.close();
  }

  // a fresh client on a dead URL must surface the cached license
  c = client({ baseUrl: 'http://127.0.0.1:1/api/', licensePath: licPath });
  try {
    assert.strictEqual(c.check(), LicenseStatus.Valid);
  } finally {
    c.close();
  }

  c = client({ licensePath: licPath });
  try {
    assert.strictEqual(c.check(), LicenseStatus.Valid);
    assert.strictEqual(c.deactivate(), LicenseStatus.ReceiptUnregistered);
  } finally {
    c.close();
  }
});

test('invalid api key surfaces InvalidApiKey', async () => {
  await setState({ failStatus: 401 });
  const c = client();
  try {
    assert.throws(
      () => c.check(),
      (err) => err instanceof LicenseError &&
               err.code === LicenseErrorCode.InvalidApiKey);
  } finally {
    c.close();
  }
});

test('trial quota exhaustion carries the server detail', async () => {
  await setState({
    failStatus: 402,
    failBody: JSON.stringify({
      error: 'trial_quota',
      detail: 'Active-trial quota exhausted for this vendor.',
    }),
  });
  const c = client();
  try {
    assert.throws(
      () => c.check(),
      (err) => err instanceof LicenseError &&
               err.code === LicenseErrorCode.TrialQuotaExceeded &&
               err.detail.includes('quota'));
  } finally {
    c.close();
  }
});

test('offline without cache reports network failure', () => {
  const c = client({ baseUrl: 'http://127.0.0.1:1/api/' });
  try {
    assert.throws(
      () => c.check(),
      (err) => err instanceof LicenseError &&
               err.code === LicenseErrorCode.NetworkFailure);
  } finally {
    c.close();
  }
});
