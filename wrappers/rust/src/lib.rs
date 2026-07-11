//! # hymmalm — Rust wrapper for license-management-core
//!
//! Safe Rust binding over the vendored native `hymmalm` core
//! (`include/hymma/hlm_ffi.h`). All licensing logic — JWS verification,
//! status rules, machine fingerprinting, the REST client flow, retry policy
//! and clock-tamper resistance — lives in the native core, so every language
//! wrapper behaves identically. This crate only marshals. The C sources are
//! compiled by `build.rs` and linked statically, so the crate is fully
//! self-contained (no shared library to ship) — ideal for Tauri apps.
//!
//! Typical use:
//!
//! ```no_run
//! use hymmalm::{LicenseClient, LicenseClientOptions, LicenseStatus};
//!
//! let mut client = LicenseClient::new(LicenseClientOptions {
//!     product_id: "PRD_01KWWPEPM0N070BDAHJ7G09RGV".into(),
//!     client_api_key: "PUB_...".into(),               // never a MST_ key
//!     jwks_json: std::fs::read_to_string("signingkeys.json").unwrap(),
//!     license_path: Some("/home/me/.myapp/license.lic".into()),
//!     ..Default::default()
//! })?;
//!
//! let status = client.check()?;                       // trial bootstrap on first run
//! if status == LicenseStatus::InvalidTrial {
//!     client.activate("RCPT-CODE-FROM-USER")?;
//! }
//! # Ok::<(), hymmalm::LicenseError>(())
//! ```
//!
//! Offline verification only (no network, e.g. checking a provisioned file):
//!
//! ```no_run
//! # let (jws_string, jwks_json) = (String::new(), String::new());
//! let status = hymmalm::verify(&jws_string, &jwks_json, None, None, None)?;
//! # Ok::<(), hymmalm::LicenseError>(())
//! ```

pub mod ffi;

use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `HLM_TIME_NONE` — the native "no timestamp" sentinel.
const TIME_NONE: i64 = i64::MIN;

/// Signed-license wire formats the server can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SignedFormat {
    #[default]
    Rs256 = 1,
    Es256 = 2,
    EdDsa = 3,
}

/// Mirrors the native `hlm_status` / the .NET SDK's LicenseStatusTitles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LicenseStatus {
    Unknown = 0,
    Expired = 1,
    Valid = 2,
    ValidTrial = 3,
    InvalidTrial = 4,
    ReceiptExpired = 5,
    ReceiptUnregistered = 6,
}

impl LicenseStatus {
    /// Map a native status code to the enum; unrecognized codes become
    /// [`LicenseStatus::Unknown`].
    pub fn from_code(code: i32) -> LicenseStatus {
        match code {
            1 => LicenseStatus::Expired,
            2 => LicenseStatus::Valid,
            3 => LicenseStatus::ValidTrial,
            4 => LicenseStatus::InvalidTrial,
            5 => LicenseStatus::ReceiptExpired,
            6 => LicenseStatus::ReceiptUnregistered,
            _ => LicenseStatus::Unknown,
        }
    }
}

/// Error reported by the native core.
///
/// `code` is the native `hlm_err` value; `detail` carries the server's
/// human-readable refusal reason when it sent one. Well-known codes:
///
/// | code | meaning |
/// |-----:|---------|
/// | -1  | invalid argument |
/// | -2  | buffer too small |
/// | -3  | malformed input |
/// | -4  | signature invalid |
/// | -5  | unsupported algorithm |
/// | -6  | no license |
/// | -7  | network failure |
/// | -8  | API rejected |
/// | -9  | storage failure |
/// | -10 | product mismatch |
/// | -11 | computer mismatch |
/// | -12 | invalid API key |
/// | -13 | trial quota exceeded |
/// | -14 | paid format required |
/// | -15 | plan limit reached |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseError {
    pub code: i32,
    pub detail: String,
}

impl LicenseError {
    fn new(code: i32, detail: String) -> LicenseError {
        LicenseError { code, detail }
    }

    /// The native core's short name for `code` (e.g. `"signature invalid"`).
    pub fn name(&self) -> String {
        // Stateless: hlm_ffi_err_name returns a static string.
        unsafe { copy_c_str(ffi::hlm_ffi_err_name(self.code as c_int)) }
    }
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "{}", self.name())
        } else {
            write!(f, "{}: {}", self.name(), self.detail)
        }
    }
}

impl std::error::Error for LicenseError {}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, LicenseError>;

/// Options for [`LicenseClient::new`]. `product_id`, `client_api_key` and
/// `jwks_json` are required; everything else has a sensible default.
#[derive(Debug, Clone, Default)]
pub struct LicenseClientOptions {
    /// `None` => `https://license-management.com/api/`.
    pub base_url: Option<String>,
    /// Required: `PRD_...`.
    pub product_id: String,
    /// Required: `PUB_...` (never a `MST_` key).
    pub client_api_key: String,
    /// Required: one JWK object or a JSON array of JWKs — the vendor's
    /// public keys, from `/api/signingkeys.json`.
    pub jwks_json: String,
    /// Signed-license wire format (default RS256).
    pub format: SignedFormat,
    /// `0` => 90.
    pub valid_days: u32,
    /// `None` => derive from hardware.
    pub machine_id: Option<String>,
    /// `None` => this computer's name.
    pub machine_name: Option<String>,
    /// `None` => no offline cache; else the `.lic` cache file.
    pub license_path: Option<PathBuf>,
}

/// High-level licensing client (check / activate / deactivate / refresh).
///
/// # Thread-safety
///
/// The native handle must not be used from two threads at once ("one handle
/// per thread, or serialize calls yourself"). `LicenseClient` is therefore
/// `Send` but **not** `Sync`: you can move it between threads (or wrap it in
/// a `Mutex`, e.g. in Tauri managed state), but you cannot share `&LicenseClient`
/// across threads.
pub struct LicenseClient {
    handle: *mut ffi::HlmFfiClient,
}

// Safe: the native handle has no thread affinity — it only requires that
// calls on it are serialized, which `Send + !Sync` (or an external Mutex)
// guarantees.
unsafe impl Send for LicenseClient {}

impl LicenseClient {
    /// Create a client. Fails with code `-1` when the native core rejects
    /// the options (missing product/key/JWKS, or no machine fingerprint
    /// available on this platform).
    pub fn new(options: LicenseClientOptions) -> Result<LicenseClient> {
        let base_url = opt_cstring(options.base_url.as_deref())?;
        let product_id = cstring(&options.product_id)?;
        let client_api_key = cstring(&options.client_api_key)?;
        let jwks_json = cstring(&options.jwks_json)?;
        let machine_id = opt_cstring(options.machine_id.as_deref())?;
        let machine_name = opt_cstring(options.machine_name.as_deref())?;
        let license_path = match &options.license_path {
            None => None,
            Some(p) => Some(cstring(p.to_str().ok_or_else(|| {
                LicenseError::new(-1, "license_path is not valid UTF-8".into())
            })?)?),
        };

        let handle = unsafe {
            ffi::hlm_ffi_create(
                opt_ptr(&base_url),
                product_id.as_ptr(),
                client_api_key.as_ptr(),
                jwks_json.as_ptr(),
                options.format as c_int,
                options.valid_days,
                opt_ptr(&machine_id),
                opt_ptr(&machine_name),
                opt_ptr(&license_path),
            )
        };
        if handle.is_null() {
            return Err(LicenseError::new(
                -1,
                "hlm_ffi_create rejected the options (missing product/key/JWKS, \
                 or no machine fingerprint available on this platform)"
                    .into(),
            ));
        }
        Ok(LicenseClient { handle })
    }

    fn guard(&mut self, err: c_int) -> Result<LicenseStatus> {
        if err != 0 {
            let detail = unsafe { copy_c_str(ffi::hlm_ffi_last_error_detail(self.handle)) };
            return Err(LicenseError::new(err, detail));
        }
        Ok(self.status())
    }

    // -- operations ------------------------------------------------------

    /// Silent check; on a fresh machine this also bootstraps the trial.
    pub fn check(&mut self) -> Result<LicenseStatus> {
        let r = unsafe { ffi::hlm_ffi_check(self.handle) };
        self.guard(r)
    }

    /// Attach a purchased receipt code to this machine's license.
    pub fn activate(&mut self, receipt_code: &str) -> Result<LicenseStatus> {
        let code = cstring(receipt_code)?;
        let r = unsafe { ffi::hlm_ffi_activate(self.handle, code.as_ptr()) };
        self.guard(r)
    }

    /// Free this machine's seat (uninstall flow).
    pub fn deactivate(&mut self) -> Result<LicenseStatus> {
        let r = unsafe { ffi::hlm_ffi_deactivate(self.handle) };
        self.guard(r)
    }

    /// Fetch a fresh signed license, ignoring the cache.
    pub fn refresh(&mut self) -> Result<LicenseStatus> {
        let r = unsafe { ffi::hlm_ffi_refresh(self.handle) };
        self.guard(r)
    }

    // -- state -------------------------------------------------------------

    pub fn status(&self) -> LicenseStatus {
        LicenseStatus::from_code(unsafe { ffi::hlm_ffi_status(self.handle) })
    }

    pub fn license_id(&self) -> String {
        unsafe { copy_c_str(ffi::hlm_ffi_license_id(self.handle)) }
    }

    pub fn product_name(&self) -> String {
        unsafe { copy_c_str(ffi::hlm_ffi_product_name(self.handle)) }
    }

    pub fn buyer_email(&self) -> String {
        unsafe { copy_c_str(ffi::hlm_ffi_buyer_email(self.handle)) }
    }

    pub fn live_mode(&self) -> bool {
        unsafe { ffi::hlm_ffi_live_mode(self.handle) != 0 }
    }

    pub fn expires(&self) -> Option<SystemTime> {
        from_unix(unsafe { ffi::hlm_ffi_expires(self.handle) })
    }

    pub fn trial_end(&self) -> Option<SystemTime> {
        from_unix(unsafe { ffi::hlm_ffi_trial_end(self.handle) })
    }

    pub fn receipt_expires(&self) -> Option<SystemTime> {
        from_unix(unsafe { ffi::hlm_ffi_receipt_expires(self.handle) })
    }

    /// Value of a metadata entry attached to the license ("" when absent).
    pub fn metadata(&self, key: &str) -> String {
        let Ok(key) = CString::new(key) else {
            return String::new();
        };
        unsafe { copy_c_str(ffi::hlm_ffi_metadata(self.handle, key.as_ptr())) }
    }

    /// The HTTP status of the last server round-trip (0 when none).
    pub fn last_http_status(&self) -> i32 {
        unsafe { ffi::hlm_ffi_last_http_status(self.handle) }
    }
}

impl Drop for LicenseClient {
    fn drop(&mut self) {
        unsafe { ffi::hlm_ffi_destroy(self.handle) };
    }
}

impl fmt::Debug for LicenseClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicenseClient")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

// -- free functions ---------------------------------------------------------

/// This machine's hardware fingerprint (52-char Crockford Base32) —
/// identical to the .NET SDK's DeviceId on the same machine.
pub fn machine_id() -> Result<String> {
    let mut buf = [0u8; 64];
    let r = unsafe { ffi::hlm_ffi_machine_id(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int) };
    if r != 0 {
        return Err(LicenseError::new(r, String::new()));
    }
    Ok(buf_to_string(&buf))
}

/// This computer's name, as the SDK would send it.
pub fn machine_name() -> Result<String> {
    let mut buf = [0u8; 256];
    let r =
        unsafe { ffi::hlm_ffi_machine_name(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int) };
    if r != 0 {
        return Err(LicenseError::new(r, String::new()));
    }
    Ok(buf_to_string(&buf))
}

/// Offline one-shot: verify a signed license string against `jwks_json` and
/// report its status at `now` (default: the system clock). Fails with code
/// `-3`/`-4` when the string is malformed or tampered, `-10`/`-11` when the
/// product/machine binding does not match.
pub fn verify(
    jws: &str,
    jwks_json: &str,
    expected_product_id: Option<&str>,
    expected_machine_id: Option<&str>,
    now: Option<SystemTime>,
) -> Result<LicenseStatus> {
    let jws = cstring(jws)?;
    let jwks = cstring(jwks_json)?;
    let product = opt_cstring(expected_product_id)?;
    let machine = opt_cstring(expected_machine_id)?;
    let unix: i64 = match now {
        None => 0,
        Some(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        },
    };
    let mut status: c_int = 0;
    let r = unsafe {
        ffi::hlm_ffi_verify(
            jws.as_ptr(),
            jwks.as_ptr(),
            opt_ptr(&product),
            opt_ptr(&machine),
            unix,
            &mut status,
        )
    };
    if r != 0 {
        return Err(LicenseError::new(r, String::new()));
    }
    Ok(LicenseStatus::from_code(status))
}

// -- marshalling helpers ------------------------------------------------------

fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| LicenseError::new(-1, "string contains a NUL byte".into()))
}

fn opt_cstring(s: Option<&str>) -> Result<Option<CString>> {
    s.map(cstring).transpose()
}

fn opt_ptr(s: &Option<CString>) -> *const c_char {
    s.as_ref().map_or(ptr::null(), |c| c.as_ptr())
}

/// Copy a borrowed native string immediately — it is only valid until the
/// next call on the handle. NULL becomes "".
unsafe fn copy_c_str(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

fn buf_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn from_unix(seconds: i64) -> Option<SystemTime> {
    if seconds == TIME_NONE {
        return None;
    }
    Some(if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    })
}
