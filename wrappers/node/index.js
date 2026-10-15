'use strict';

/* hymmalm — Node.js wrapper for license-management-core.
 *
 * Thin koffi binding over the native `hymmalm` shared library
 * (include/hymma/hlm_ffi.h). All licensing logic — JWS verification,
 * status rules, machine fingerprinting, the REST client flow, retry
 * policy and clock-tamper resistance — lives in the native core, so
 * every language wrapper behaves identically. This module only marshals.
 *
 * Typical use:
 *
 *   const { LicenseClient, LicenseStatus } = require('hymmalm');
 *
 *   const client = new LicenseClient({
 *     productId: 'PRD_01KWWPEPM0N070BDAHJ7G09RGV',
 *     clientApiKey: 'PUB_...',                    // never a MST_ key
 *     jwksJson: fs.readFileSync('signingkeys.json', 'utf8'),
 *     licensePath: path.join(os.homedir(), '.myapp', 'license.lic'),
 *   });
 *   const status = client.check();                // trial bootstrap on first run
 *   if (status === LicenseStatus.InvalidTrial) client.activate(userEnteredCode);
 *
 * The native library is located via the HYMMALM_LIB environment variable
 * (full path), or the standard loader search for libhymmalm.so /
 * libhymmalm.dylib / hymmalm.dll.
 */

const koffi = require('koffi');
const fs = require('node:fs');
const path = require('node:path');

/* Native int64 sentinel HLM_TIME_NONE is INT64_MIN; koffi hands int64
 * back as a JS number, so anything below -1e15 means "no timestamp". */
const TIME_NONE_FLOOR = -1e15;

/** Signed-license wire formats the server can emit. */
const SignedFormat = Object.freeze({
  RS256: 1,
  ES256: 2,
  EDDSA: 3,
});

/** Mirrors the native hlm_status / the .NET SDK's LicenseStatusTitles. */
const LicenseStatus = Object.freeze({
  Unknown: 0,
  Expired: 1,
  Valid: 2,
  ValidTrial: 3,
  InvalidTrial: 4,
  ReceiptExpired: 5,
  ReceiptUnregistered: 6,
});

/** Classified reasons the core or the server can refuse an operation. */
const LicenseErrorCode = Object.freeze({
  InvalidArgument: -1,
  BufferTooSmall: -2,
  MalformedInput: -3,
  SignatureInvalid: -4,
  UnsupportedAlgorithm: -5,
  NoLicense: -6,
  NetworkFailure: -7,
  ApiRejected: -8,
  StorageFailure: -9,
  ProductMismatch: -10,
  ComputerMismatch: -11,
  InvalidApiKey: -12,
  TrialQuotaExceeded: -13,
  PaidFormatRequired: -14,
  PlanLimitReached: -15,
});

/** Why the license server could not be reached (native hlm_net_failure;
 *  the .NET SDK's NetworkFailureReason). */
const NetworkFailure = Object.freeze({
  None: 0,
  Unknown: 1,
  NameResolution: 2,   // DNS returned no address (company DNS filter)
  SecureConnection: 3, // TLS handshake / certificate failure
  Proxy: 4,            // proxy refused, failed, or demanded auth (407)
  Timeout: 5,
  Connection: 6,       // address found; connection refused or dropped
});

/** Outcome of LicenseClient#importLicense (native hlm_import_result;
 *  the .NET SDK's LicenseImportOutcome). */
const LicenseImportOutcome = Object.freeze({
  Installed: 0,
  NotALicenseFile: 1,
  NoPublicKey: 2,
  SignatureInvalid: 3,
  WrongProduct: 4,
  WrongComputer: 5,
  WriteFailed: 6,
});

/* ---------------------------------------------------------------------- */
/* native library loading                                                  */
/* ---------------------------------------------------------------------- */

let _native = null;

function candidates() {
  const list = [];
  if (process.env.HYMMALM_LIB) list.push(process.env.HYMMALM_LIB);
  const names =
    process.platform === 'win32' ? ['hymmalm.dll']
    : process.platform === 'darwin' ? ['libhymmalm.dylib']
    : ['libhymmalm.so'];
  for (const name of names) {
    // published releases bundle one library per platform under prebuilt/
    list.push(path.join(__dirname, 'prebuilt',
                        `${process.platform}-${process.arch}`, name));
    list.push(path.join(__dirname, name)); // dropped alongside the package
    list.push(name); // standard loader search
  }
  return list;
}

function native() {
  if (_native) return _native;
  let lib = null;
  let lastErr = null;
  for (const cand of candidates()) {
    try {
      lib = koffi.load(cand);
      break;
    } catch (e) {
      lastErr = e;
    }
  }
  if (!lib) {
    throw new Error(
      'cannot load the native hymmalm library; build it with cmake and set ' +
      'HYMMALM_LIB to the full path of libhymmalm.so/.dylib/hymmalm.dll',
      { cause: lastErr });
  }

  koffi.opaque('hlm_ffi_client');

  _native = {
    create: lib.func(
      'hlm_ffi_client *hlm_ffi_create(const char *base_url,' +
      ' const char *product_id, const char *client_api_key,' +
      ' const char *jwks_json, int format, uint valid_days,' +
      ' const char *machine_id, const char *machine_name,' +
      ' const char *license_path)'),
    destroy: lib.func('void hlm_ffi_destroy(hlm_ffi_client *c)'),
    check: lib.func('int hlm_ffi_check(hlm_ffi_client *c)'),
    activate: lib.func(
      'int hlm_ffi_activate(hlm_ffi_client *c, const char *receipt_code)'),
    deactivate: lib.func('int hlm_ffi_deactivate(hlm_ffi_client *c)'),
    refresh: lib.func('int hlm_ffi_refresh(hlm_ffi_client *c)'),
    status: lib.func('int hlm_ffi_status(hlm_ffi_client *c)'),
    statusName: lib.func('const char *hlm_ffi_status_name(hlm_ffi_client *c)'),
    licenseId: lib.func('const char *hlm_ffi_license_id(hlm_ffi_client *c)'),
    productName: lib.func(
      'const char *hlm_ffi_product_name(hlm_ffi_client *c)'),
    buyerEmail: lib.func('const char *hlm_ffi_buyer_email(hlm_ffi_client *c)'),
    expires: lib.func('int64 hlm_ffi_expires(hlm_ffi_client *c)'),
    trialEnd: lib.func('int64 hlm_ffi_trial_end(hlm_ffi_client *c)'),
    receiptExpires: lib.func(
      'int64 hlm_ffi_receipt_expires(hlm_ffi_client *c)'),
    liveMode: lib.func('int hlm_ffi_live_mode(hlm_ffi_client *c)'),
    metadata: lib.func(
      'const char *hlm_ffi_metadata(hlm_ffi_client *c, const char *key)'),
    lastHttpStatus: lib.func(
      'int hlm_ffi_last_http_status(hlm_ffi_client *c)'),
    lastErrorDetail: lib.func(
      'const char *hlm_ffi_last_error_detail(hlm_ffi_client *c)'),
    lastNetworkFailure: lib.func(
      'int hlm_ffi_last_network_failure(hlm_ffi_client *c)'),
    importLicense: lib.func(
      'int hlm_ffi_import_license(hlm_ffi_client *c, const char *document)'),
    licensePath: lib.func(
      'const char *hlm_ffi_license_path(hlm_ffi_client *c)'),
    errName: lib.func('const char *hlm_ffi_err_name(int err)'),
    machineId: lib.func('int hlm_ffi_machine_id(uint8_t *out, int cap)'),
    machineName: lib.func('int hlm_ffi_machine_name(uint8_t *out, int cap)'),
    verify: lib.func(
      'int hlm_ffi_verify(const char *jws, const char *jwks_json,' +
      ' const char *expected_product_id, const char *expected_machine_id,' +
      ' int64 now, _Out_ int *status_out)'),
  };
  return _native;
}

/* ---------------------------------------------------------------------- */
/* errors                                                                  */
/* ---------------------------------------------------------------------- */

/**
 * Thrown when the native core reports an error. `code` is the
 * LicenseErrorCode; `detail` carries the server's human-readable
 * refusal reason when it sent one — or, for NetworkFailure, a message that
 * says what failed and names the host to allow, with the cause in
 * `networkFailure`.
 */
class LicenseError extends Error {
  constructor(code, detail = '', networkFailure = NetworkFailure.None) {
    const name = native().errName(code);
    super(detail ? `${name}: ${detail}` : name);
    this.name = 'LicenseError';
    this.code = code;
    this.detail = detail;
    this.networkFailure = networkFailure;
  }
}

/* ---------------------------------------------------------------------- */
/* helpers                                                                 */
/* ---------------------------------------------------------------------- */

function fromUnix(seconds) {
  const s = typeof seconds === 'bigint' ? Number(seconds) : seconds;
  if (!Number.isFinite(s) || s < TIME_NONE_FLOOR) return null;
  return new Date(s * 1000);
}

function bufToString(buf) {
  const nul = buf.indexOf(0);
  return buf.toString('utf8', 0, nul < 0 ? buf.length : nul);
}

/**
 * This machine's hardware fingerprint (52-char Crockford Base32) —
 * identical to the .NET SDK's DeviceId on the same machine.
 */
function machineId() {
  const buf = Buffer.alloc(64);
  const r = native().machineId(buf, buf.length);
  if (r !== 0) throw new LicenseError(r);
  return bufToString(buf);
}

/** This computer's name, as the SDK would send it. */
function machineName() {
  const buf = Buffer.alloc(256);
  const r = native().machineName(buf, buf.length);
  if (r !== 0) throw new LicenseError(r);
  return bufToString(buf);
}

/**
 * Offline one-shot: verify a signed license string and report its status
 * at `nowDate` (default: the system clock). Throws LicenseError when the
 * string is tampered or malformed.
 */
function verify(jws, jwksJson, expectedProductId = null,
                expectedMachineId = null, nowDate = null) {
  const now = nowDate ? Math.floor(nowDate.getTime() / 1000) : 0;
  const out = [0];
  const r = native().verify(jws, jwksJson, expectedProductId,
                            expectedMachineId, now, out);
  if (r !== 0) throw new LicenseError(r);
  return out[0];
}

/* ---------------------------------------------------------------------- */
/* client                                                                  */
/* ---------------------------------------------------------------------- */

/**
 * High-level licensing client (check / activate / deactivate / refresh).
 *
 * One instance per thread, or serialize calls yourself — same rule as the
 * native handle it wraps.
 */
class LicenseClient {
  /**
   * @param {object} options
   *   {baseUrl, productId, clientApiKey, jwksJson, format, validDays,
   *    machineId, machineName, licensePath}
   */
  constructor(options) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('LicenseClient requires an options object');
    }
    const {
      baseUrl = null,
      productId,
      clientApiKey,
      jwksJson,
      format = SignedFormat.RS256,
      validDays = 0,
      machineId = null,
      machineName = null,
      licensePath = null,
    } = options;

    this._h = native().create(baseUrl, productId, clientApiKey, jwksJson,
                              format, validDays, machineId, machineName,
                              licensePath);
    if (!this._h) {
      throw new Error(
        'hlm_ffi_create rejected the options (missing product/key/JWKS, ' +
        'or no machine fingerprint available on this platform)');
    }
  }

  /* -- lifecycle ------------------------------------------------------- */

  close() {
    if (this._h) {
      native().destroy(this._h);
      this._h = null;
    }
  }

  get _handle() {
    if (!this._h) throw new Error('LicenseClient is closed');
    return this._h;
  }

  _guard(err) {
    if (err !== 0) {
      const detail = native().lastErrorDetail(this._handle) || '';
      const failure = err === LicenseErrorCode.NetworkFailure
        ? this.lastNetworkFailure : NetworkFailure.None;
      throw new LicenseError(err, detail, failure);
    }
    return this.status;
  }

  /**
   * Install a signed license the user obtained outside the online flow
   * (vendor portal, email) on a computer that cannot reach the server.
   * Verified exactly as the offline cache is — vendor signature, product,
   * this computer — before it replaces anything, so a wrong or tampered
   * file never displaces a working one. Never touches the network.
   * @returns {{outcome:number, succeeded:boolean, message:string, installedPath:(string|null)}}
   */
  importLicense(document) {
    const r = native().importLicense(this._handle, document);
    if (r < 0) throw new LicenseError(r);
    return {
      outcome: r,
      succeeded: r === LicenseImportOutcome.Installed,
      message: native().lastErrorDetail(this._handle) || '',
      installedPath: r === LicenseImportOutcome.Installed ? this.licensePath : null,
    };
  }

  /** Read, verify and install the license file at `filePath`. */
  importLicenseFile(filePath) {
    let document;
    try {
      document = fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      return {
        outcome: LicenseImportOutcome.NotALicenseFile,
        succeeded: false,
        message: `The file could not be read: ${e.message}`,
        installedPath: null,
      };
    }
    return this.importLicense(document);
  }

  /** Why the server could not be reached on the last call (NetworkFailure);
   *  also set when check() succeeded from the cached file because the
   *  network failed. */
  get lastNetworkFailure() {
    return native().lastNetworkFailure(this._handle);
  }

  /** The license cache file this client reads and writes ('' when none). */
  get licensePath() {
    return native().licensePath(this._handle) || '';
  }

  /* -- operations ------------------------------------------------------ */

  /** Silent check; on a fresh machine this also bootstraps the trial. */
  check() {
    return this._guard(native().check(this._handle));
  }

  /** Attach a purchased receipt code to this machine's license. */
  activate(receiptCode) {
    return this._guard(native().activate(this._handle, receiptCode));
  }

  /** Free this machine's seat (uninstall flow). */
  deactivate() {
    return this._guard(native().deactivate(this._handle));
  }

  /** Fetch a fresh signed license, ignoring the cache. */
  refresh() {
    return this._guard(native().refresh(this._handle));
  }

  /* -- state ------------------------------------------------------------ */

  get status() {
    return native().status(this._handle);
  }

  get licenseId() {
    return native().licenseId(this._handle) || '';
  }

  get productName() {
    return native().productName(this._handle) || '';
  }

  get buyerEmail() {
    return native().buyerEmail(this._handle) || '';
  }

  get liveMode() {
    return native().liveMode(this._handle) !== 0;
  }

  get expires() {
    return fromUnix(native().expires(this._handle));
  }

  get trialEnd() {
    return fromUnix(native().trialEnd(this._handle));
  }

  get receiptExpires() {
    return fromUnix(native().receiptExpires(this._handle));
  }

  get lastHttpStatus() {
    return native().lastHttpStatus(this._handle);
  }

  metadata(key) {
    return native().metadata(this._handle, key) || '';
  }
}

module.exports = {
  LicenseClient,
  LicenseStatus,
  SignedFormat,
  LicenseErrorCode,
  LicenseError,
  NetworkFailure,
  LicenseImportOutcome,
  machineId,
  machineName,
  verify,
};
