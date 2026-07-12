/** hymmalm — Node.js wrapper for license-management-core. */

/** Signed-license wire formats the server can emit. */
export declare const SignedFormat: Readonly<{
  RS256: 1;
  ES256: 2;
  EDDSA: 3;
}>;
export type SignedFormat = (typeof SignedFormat)[keyof typeof SignedFormat];

/** Mirrors the native hlm_status / the .NET SDK's LicenseStatusTitles. */
export declare const LicenseStatus: Readonly<{
  Unknown: 0;
  Expired: 1;
  Valid: 2;
  ValidTrial: 3;
  InvalidTrial: 4;
  ReceiptExpired: 5;
  ReceiptUnregistered: 6;
}>;
export type LicenseStatus = (typeof LicenseStatus)[keyof typeof LicenseStatus];

/** Classified reasons the core or the server can refuse an operation. */
export declare const LicenseErrorCode: Readonly<{
  InvalidArgument: -1;
  BufferTooSmall: -2;
  MalformedInput: -3;
  SignatureInvalid: -4;
  UnsupportedAlgorithm: -5;
  NoLicense: -6;
  NetworkFailure: -7;
  ApiRejected: -8;
  StorageFailure: -9;
  ProductMismatch: -10;
  ComputerMismatch: -11;
  InvalidApiKey: -12;
  TrialQuotaExceeded: -13;
  PaidFormatRequired: -14;
  PlanLimitReached: -15;
}>;
export type LicenseErrorCode =
  (typeof LicenseErrorCode)[keyof typeof LicenseErrorCode];

/**
 * Thrown when the native core reports an error. `code` is the native
 * error code (a LicenseErrorCode value); `detail` carries the server's
 * human-readable refusal reason when it sent one.
 */
export declare class LicenseError extends Error {
  constructor(code: number, detail?: string);
  code: number;
  detail: string;
}

export interface LicenseClientOptions {
  /** Server base URL; omit to use https://license-management.com/api/. */
  baseUrl?: string | null;
  /** The sellable product (PRD_...). Required. */
  productId: string;
  /** The vendor's CLIENT key (PUB_...). Never ship a MST_ key. Required. */
  clientApiKey: string;
  /** Vendor public key(s): one JWK object or a JSON array of JWKs. Required. */
  jwksJson: string;
  /** Signed-license wire format. Default: SignedFormat.RS256. */
  format?: SignedFormat | number;
  /** Requested license-file validity window; 0 => server default (90). */
  validDays?: number;
  /** Override the hardware fingerprint (tests, containers). */
  machineId?: string | null;
  machineName?: string | null;
  /** Offline cache path for the signed license; omit to disable caching. */
  licensePath?: string | null;
}

/**
 * High-level licensing client (check / activate / deactivate / refresh).
 * One instance per thread, or serialize calls yourself.
 */
export declare class LicenseClient {
  constructor(options: LicenseClientOptions);

  /** Silent check; on a fresh machine this also bootstraps the trial. */
  check(): LicenseStatus;
  /** Attach a purchased receipt code to this machine's license. */
  activate(receiptCode: string): LicenseStatus;
  /** Free this machine's seat (uninstall flow). */
  deactivate(): LicenseStatus;
  /** Fetch a fresh signed license, ignoring the cache. */
  refresh(): LicenseStatus;

  readonly status: LicenseStatus;
  readonly licenseId: string;
  readonly productName: string;
  readonly buyerEmail: string;
  readonly liveMode: boolean;
  readonly expires: Date | null;
  readonly trialEnd: Date | null;
  readonly receiptExpires: Date | null;
  readonly lastHttpStatus: number;

  metadata(key: string): string;
  close(): void;
}

/**
 * This machine's hardware fingerprint (52-char Crockford Base32) —
 * identical to the .NET SDK's DeviceId on the same machine.
 */
export declare function machineId(): string;

/** This computer's name, as the SDK would send it. */
export declare function machineName(): string;

/**
 * Offline one-shot: verify a signed license string and report its status
 * at `nowDate` (default: the system clock). Throws LicenseError when the
 * string is tampered or malformed.
 */
export declare function verify(
  jws: string,
  jwksJson: string,
  expectedProductId?: string | null,
  expectedMachineId?: string | null,
  nowDate?: Date | null,
): LicenseStatus;
