'use strict';

/* Vector-driven compatibility tests: the wrapper must verify exactly what
 * the license server signs (tests/vectors/*.json) and reject tampered
 * tokens, matching the C test suite case for case. */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const hymmalm = require('../index.js');
const { LicenseError, LicenseErrorCode, LicenseStatus } = hymmalm;

const REPO = path.resolve(__dirname, '..', '..', '..');
const VECTOR_FILES = ['vectors.json', 'vectors-eddsa.json'];

const STATUS_BY_NAME = {
  Unknown: LicenseStatus.Unknown,
  Expired: LicenseStatus.Expired,
  Valid: LicenseStatus.Valid,
  ValidTrial: LicenseStatus.ValidTrial,
  InvalidTrial: LicenseStatus.InvalidTrial,
  ReceiptExpired: LicenseStatus.ReceiptExpired,
  ReceiptUnregistered: LicenseStatus.ReceiptUnregistered,
};

function load(name) {
  return JSON.parse(
    fs.readFileSync(path.join(REPO, 'tests', 'vectors', name), 'utf8'));
}

function jwksOf(vec) {
  const keys = ['RsaJwk', 'EcJwk', 'EdJwk']
    .filter((k) => k in vec)
    .map((k) => vec[k]);
  return JSON.stringify(keys);
}

function parseNow(c) {
  return c.NowUtc ? new Date(c.NowUtc) : null;
}

test('all vector cases', () => {
  for (const fname of VECTOR_FILES) {
    const vec = load(fname);
    const jwks = jwksOf(vec);
    for (const c of vec.Cases) {
      const label = `${fname}: ${c.Name}`;
      if (c.Valid) {
        const status = hymmalm.verify(c.Jws, jwks, null, null, parseNow(c));
        if ('ExpectedStatus' in c) {
          assert.strictEqual(status, STATUS_BY_NAME[c.ExpectedStatus], label);
        }
      } else {
        assert.throws(
          () => hymmalm.verify(c.Jws, jwks, null, null, parseNow(c)),
          (err) =>
            err instanceof LicenseError &&
            (err.code === LicenseErrorCode.SignatureInvalid ||
             err.code === LicenseErrorCode.MalformedInput),
          label);
      }
    }
  }
});

test('product and machine binding', () => {
  const vec = load('vectors.json');
  const jwks = jwksOf(vec);
  const c = vec.Cases.find((x) => x.Name === 'rs256-trial-valid');
  const now = parseNow(c);
  const mac = 'KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG';

  assert.strictEqual(
    hymmalm.verify(c.Jws, jwks, 'PRD_01KWWPEPM0N070BDAHJ7G09RGV', mac, now),
    LicenseStatus.ValidTrial);

  assert.throws(
    () => hymmalm.verify(c.Jws, jwks, 'PRD_SOMETHINGELSE', mac, now),
    (err) => err instanceof LicenseError &&
             err.code === LicenseErrorCode.ProductMismatch);

  assert.throws(
    () => hymmalm.verify(c.Jws, jwks, 'PRD_01KWWPEPM0N070BDAHJ7G09RGV',
                         'WRONGMACHINE', now),
    (err) => err instanceof LicenseError &&
             err.code === LicenseErrorCode.ComputerMismatch);
});

test('machine identity', () => {
  assert.strictEqual(hymmalm.machineId().length, 52);
  assert.ok(hymmalm.machineName().length > 0);
});

test('error names', () => {
  const err = new LicenseError(LicenseErrorCode.SignatureInvalid);
  assert.ok(String(err.message).includes('signature'), err.message);
});
