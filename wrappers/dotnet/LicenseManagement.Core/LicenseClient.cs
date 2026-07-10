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

    public sealed class LicenseException : Exception
    {
        public int NativeError { get; }

        internal LicenseException(int err)
            : base(NativeMethods.Str(NativeMethods.hlm_ffi_err_name(err)))
        {
            NativeError = err;
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

        /// <summary>This machine's fingerprint — identical to the classic .NET SDK's.</summary>
        public static string GetMachineId()
        {
            var buf = new byte[64];
            var r = NativeMethods.hlm_ffi_machine_id(buf, buf.Length);
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
            if (err != 0) throw new LicenseException(err);
            return Status;
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
