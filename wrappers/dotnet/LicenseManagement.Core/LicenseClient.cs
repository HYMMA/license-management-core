using System;

namespace LicenseManagement.Core
{
    /// <summary>Signed-license wire formats the server can emit.</summary>
    public enum SignedFormat
    {
        Rs256 = 1,
        Es256 = 2,
        EdDsa = 3,
    }

    /// <summary>Mirrors the native hlm_status / the classic SDK's LicenseStatusTitles.</summary>
    public enum LicenseStatus
    {
        Unknown = 0,
        Expired = 1,
        Valid = 2,
        ValidTrial = 3,
        InvalidTrial = 4,
        ReceiptExpired = 5,
        ReceiptUnregistered = 6,
    }

    public sealed class LicenseClientOptions
    {
        /// <summary>Server base URL; null uses https://license-management.com/api/.</summary>
        public string? BaseUrl { get; set; }

        /// <summary>The sellable product (PRD_...).</summary>
        public string ProductId { get; set; } = string.Empty;

        /// <summary>The vendor's CLIENT key (PUB_...). Never ship a MST_ key.</summary>
        public string ClientApiKey { get; set; } = string.Empty;

        /// <summary>Vendor public key(s) as a JWK object or JSON array of JWKs
        /// (GET /api/signingkeys.json). Bake this into the app.</summary>
        public string JwksJson { get; set; } = string.Empty;

        public SignedFormat Format { get; set; } = SignedFormat.Rs256;

        /// <summary>Requested license-file validity window; 0 =&gt; server default (90).</summary>
        public uint ValidDays { get; set; }

        /// <summary>Override the hardware fingerprint (tests, containers).</summary>
        public string? MachineId { get; set; }

        public string? MachineName { get; set; }

        /// <summary>Offline cache path for the signed license; null disables caching.</summary>
        public string? LicensePath { get; set; }
    }

    /// <summary>Classified reasons the core or the server can refuse an operation.</summary>
    public enum LicenseError
    {
        None = 0,
        InvalidArgument = -1,
        BufferTooSmall = -2,
        MalformedInput = -3,
        SignatureInvalid = -4,
        UnsupportedAlgorithm = -5,
        NoLicense = -6,
        NetworkFailure = -7,
        ApiRejected = -8,
        StorageFailure = -9,
        ProductMismatch = -10,
        ComputerMismatch = -11,
        InvalidApiKey = -12,
        /// <summary>The vendor's active-trial quota is exhausted — a new trial cannot start.</summary>
        TrialQuotaExceeded = -13,
        /// <summary>The product's policy requires a paid receipt for this license format.</summary>
        PaidFormatRequired = -14,
        /// <summary>The vendor's plan cap (ALU / sandbox limit) was reached.</summary>
        PlanLimitReached = -15,
    }

    /// <summary>Why the license server could not be reached (native hlm_net_failure);
    /// same names as the classic SDK's NetworkFailureReason.</summary>
    public enum NetworkFailure
    {
        /// <summary>No transport failure on the last call.</summary>
        None = 0,
        /// <summary>The cause could not be determined.</summary>
        Unknown = 1,
        /// <summary>DNS returned no address for the server — typically a company DNS filter.</summary>
        NameResolution = 2,
        /// <summary>The TLS handshake failed — often an HTTPS-inspecting proxy or security product.</summary>
        SecureConnection = 3,
        /// <summary>A web proxy refused or failed the connection, or demanded credentials (407).</summary>
        Proxy = 4,
        /// <summary>The server did not answer in time.</summary>
        Timeout = 5,
        /// <summary>The address was found but the connection was refused or dropped.</summary>
        Connection = 6,
    }

    /// <summary>Outcome of <see cref="LicenseClient.ImportLicense"/> (native hlm_import_result);
    /// same names as the classic SDK's LicenseImportOutcome.</summary>
    public enum LicenseImportOutcome
    {
        /// <summary>Verified and installed where the client reads it.</summary>
        Installed = 0,
        /// <summary>Not a license file this library can read.</summary>
        NotALicenseFile = 1,
        /// <summary>No public key was configured, so the file could not be verified.</summary>
        NoPublicKey = 2,
        /// <summary>The signature does not verify (altered, or another vendor's file).</summary>
        SignatureInvalid = 3,
        /// <summary>The file is for a different product.</summary>
        WrongProduct = 4,
        /// <summary>The file is for a different computer.</summary>
        WrongComputer = 5,
        /// <summary>The file could not be written to the license path.</summary>
        WriteFailed = 6,
    }

    /// <summary>What happened to an imported license file, with a message written for the end user.</summary>
    public sealed class LicenseImportResult
    {
        internal LicenseImportResult(LicenseImportOutcome outcome, string message, string? installedPath)
        {
            Outcome = outcome;
            Message = message;
            InstalledPath = installedPath;
        }

        public LicenseImportOutcome Outcome { get; }
        public bool Succeeded => Outcome == LicenseImportOutcome.Installed;
        /// <summary>End-user message for the outcome, e.g. "This license file is for the computer X. ..."</summary>
        public string Message { get; }
        /// <summary>Where the file now lives, when <see cref="Succeeded"/>.</summary>
        public string? InstalledPath { get; }
    }

    public sealed class LicenseException : Exception
    {
        public int NativeError { get; }

        /// <summary>The classified refusal reason.</summary>
        public LicenseError Error => (LicenseError)NativeError;

        /// <summary>The server's human-readable refusal detail, when it sent one; for
        /// <see cref="LicenseError.NetworkFailure"/> a message that says what failed and
        /// names the host to allow.</summary>
        public string Detail { get; }

        /// <summary>For <see cref="LicenseError.NetworkFailure"/>: what failed (DNS, TLS,
        /// proxy, timeout, connection), so a UI can offer the right way out —
        /// e.g. <see cref="LicenseClient.ImportLicenseFile"/>.</summary>
        public NetworkFailure NetworkFailure { get; }

        internal LicenseException(int err, string? detail = null,
            NetworkFailure networkFailure = NetworkFailure.None)
            : base(string.IsNullOrEmpty(detail)
                ? NativeMethods.Str(NativeMethods.hlm_ffi_err_name(err))
                : $"{NativeMethods.Str(NativeMethods.hlm_ffi_err_name(err))}: {detail}")
        {
            NativeError = err;
            Detail = detail ?? string.Empty;
            NetworkFailure = networkFailure;
        }
    }

    /// <summary>
    /// Thin, allocation-light facade over the native hymmalm core. All license
    /// logic (JWS verification, status rules, fingerprinting, endpoint flow)
    /// lives in the native library so every language behaves identically;
    /// this class only marshals.
    /// </summary>
    public sealed class LicenseClient : IDisposable
    {
        private IntPtr _handle;

        public LicenseClient(LicenseClientOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            _handle = NativeMethods.hlm_ffi_create(
                options.BaseUrl,
                options.ProductId,
                options.ClientApiKey,
                options.JwksJson,
                (int)options.Format,
                options.ValidDays,
                options.MachineId,
                options.MachineName,
                options.LicensePath);

            if (_handle == IntPtr.Zero)
                throw new ArgumentException(
                    "hlm_ffi_create rejected the options (missing product/key/JWKS, " +
                    "or no hardware fingerprint available on this platform).");
        }

        /// <summary>Silent check; on a fresh machine this also bootstraps the trial.</summary>
        public LicenseStatus Check() => Guard(NativeMethods.hlm_ffi_check(Handle));

        /// <summary>Attach a purchased receipt code to this machine's license.</summary>
        public LicenseStatus Activate(string receiptCode) =>
            Guard(NativeMethods.hlm_ffi_activate(Handle, receiptCode));

        /// <summary>Free this machine's seat (uninstall flow).</summary>
        public LicenseStatus Deactivate() => Guard(NativeMethods.hlm_ffi_deactivate(Handle));

        /// <summary>Fetch a fresh signed license, ignoring the cache.</summary>
        public LicenseStatus Refresh() => Guard(NativeMethods.hlm_ffi_refresh(Handle));

        public LicenseStatus Status => (LicenseStatus)NativeMethods.hlm_ffi_status(Handle);
        public string LicenseId => NativeMethods.Str(NativeMethods.hlm_ffi_license_id(Handle));
        public string ProductName => NativeMethods.Str(NativeMethods.hlm_ffi_product_name(Handle));
        public string BuyerEmail => NativeMethods.Str(NativeMethods.hlm_ffi_buyer_email(Handle));
        public bool LiveMode => NativeMethods.hlm_ffi_live_mode(Handle) != 0;
        public int LastHttpStatus => NativeMethods.hlm_ffi_last_http_status(Handle);

        public DateTime? ExpiresUtc => FromUnix(NativeMethods.hlm_ffi_expires(Handle));
        public DateTime? TrialEndUtc => FromUnix(NativeMethods.hlm_ffi_trial_end(Handle));
        public DateTime? ReceiptExpiresUtc => FromUnix(NativeMethods.hlm_ffi_receipt_expires(Handle));

        public string GetMetadata(string key) =>
            NativeMethods.Str(NativeMethods.hlm_ffi_metadata(Handle, key));

        /// <summary>Why the server could not be reached on the last call. Also set when
        /// <see cref="Check"/> succeeded from the cached file because the network failed.</summary>
        public NetworkFailure LastNetworkFailure =>
            (NetworkFailure)NativeMethods.hlm_ffi_last_network_failure(Handle);

        /// <summary>The license cache file this client reads and writes ("" when none) —
        /// for a host UI to show where the license lives.</summary>
        public string LicensePath => NativeMethods.Str(NativeMethods.hlm_ffi_license_path(Handle));

        /// <summary>
        /// Installs a signed license the user obtained outside the online flow (vendor
        /// portal, email) on a computer that cannot reach the server. It is verified
        /// exactly as the offline cache is — vendor signature, product, this computer —
        /// before it replaces anything, so a wrong or tampered file never displaces a
        /// working one. Never touches the network.
        /// </summary>
        public LicenseImportResult ImportLicense(string document)
        {
            if (document == null) throw new ArgumentNullException(nameof(document));
            return ImportResult(NativeMethods.hlm_ffi_import_license(Handle, document));
        }

        /// <summary>Reads, verifies and installs the license file at <paramref name="sourceFilePath"/>.</summary>
        public LicenseImportResult ImportLicenseFile(string sourceFilePath)
        {
            string content;
            try
            {
                // read here, not natively: .NET opens any Unicode path
                content = System.IO.File.ReadAllText(sourceFilePath);
            }
            catch (Exception e) when (e is System.IO.IOException || e is UnauthorizedAccessException ||
                                      e is ArgumentException || e is NotSupportedException)
            {
                return new LicenseImportResult(LicenseImportOutcome.NotALicenseFile,
                    $"The file could not be read: {e.Message}", null);
            }
            return ImportLicense(content);
        }

        /// <summary>This machine's fingerprint — identical to the classic .NET SDK's.</summary>
        public static string GetMachineId()
        {
            var buf = new byte[64];
            var r = NativeMethods.hlm_ffi_machine_id(buf, buf.Length);
            if (r != 0) throw new LicenseException(r);
            return Ascii(buf);
        }

        /// <summary>Identity v2: the MachineGuid fingerprint on Windows (unique per
        /// Windows install — the v1 sources collide across machines); identical to
        /// <see cref="GetMachineId"/> on POSIX.</summary>
        public static string GetMachineIdV2()
        {
            var buf = new byte[64];
            var r = NativeMethods.hlm_ffi_machine_id_v2(buf, buf.Length);
            if (r != 0) throw new LicenseException(r);
            return Ascii(buf);
        }

        /// <summary>Offline verification of a signed license string (no client needed).</summary>
        public static LicenseStatus Verify(string jws, string jwksJson,
            string? expectedProductId = null, string? expectedMachineId = null,
            DateTime? nowUtc = null)
        {
            long now = nowUtc.HasValue
                ? (long)(nowUtc.Value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
                : 0;
            var r = NativeMethods.hlm_ffi_verify(jws, jwksJson, expectedProductId,
                                                 expectedMachineId, now, out var status);
            if (r != 0) throw new LicenseException(r);
            return (LicenseStatus)status;
        }

        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                NativeMethods.hlm_ffi_destroy(_handle);
                _handle = IntPtr.Zero;
            }
        }

        private IntPtr Handle =>
            _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(LicenseClient));

        private LicenseStatus Guard(int err)
        {
            if (err != 0)
                throw new LicenseException(err,
                    NativeMethods.Str(NativeMethods.hlm_ffi_last_error_detail(Handle)),
                    err == (int)LicenseError.NetworkFailure ? LastNetworkFailure : NetworkFailure.None);
            return Status;
        }

        private LicenseImportResult ImportResult(int r)
        {
            if (r < 0) throw new LicenseException(r);
            var outcome = (LicenseImportOutcome)r;
            return new LicenseImportResult(outcome,
                NativeMethods.Str(NativeMethods.hlm_ffi_last_error_detail(Handle)),
                outcome == LicenseImportOutcome.Installed ? LicensePath : null);
        }

        private static DateTime? FromUnix(long seconds) =>
            seconds == long.MinValue
                ? (DateTime?)null
                : new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(seconds);

        private static string Ascii(byte[] buf)
        {
            var n = Array.IndexOf(buf, (byte)0);
            return System.Text.Encoding.ASCII.GetString(buf, 0, n < 0 ? buf.Length : n);
        }
    }
}
