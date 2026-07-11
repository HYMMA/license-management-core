//! Raw `extern "C"` declarations for the flat FFI surface of
//! license-management-core (`include/hymma/hlm_ffi.h`), hand-written —
//! no bindgen.
//!
//! Thread-safety of the native handle: one handle per thread, or serialize
//! calls yourself. Returned `*const c_char` strings are owned by the handle
//! and only valid until the next call on that handle (or
//! [`hlm_ffi_destroy`]); copy them immediately.

use std::os::raw::{c_char, c_int, c_uint};

/// Opaque native client handle (`hlm_ffi_client`).
pub enum HlmFfiClient {}

extern "C" {
    /// Create a client. Returns NULL on invalid arguments.
    ///
    /// * `base_url` — NULL => `https://license-management.com/api/`
    /// * `format` — 1=RS256, 2=ES256, 3=EdDSA
    /// * `valid_days` — 0 => 90
    /// * `license_path` — NULL => no offline cache
    pub fn hlm_ffi_create(
        base_url: *const c_char,
        product_id: *const c_char,
        client_api_key: *const c_char,
        jwks_json: *const c_char,
        format: c_int,
        valid_days: c_uint,
        machine_id: *const c_char,
        machine_name: *const c_char,
        license_path: *const c_char,
    ) -> *mut HlmFfiClient;

    pub fn hlm_ffi_destroy(c: *mut HlmFfiClient);

    /// Silent check & trial bootstrap. Returns 0 (HLM_OK) or an hlm_err.
    pub fn hlm_ffi_check(c: *mut HlmFfiClient) -> c_int;
    /// Attach a purchased receipt code, then refresh.
    pub fn hlm_ffi_activate(c: *mut HlmFfiClient, receipt_code: *const c_char) -> c_int;
    /// Free this machine's seat (uninstall).
    pub fn hlm_ffi_deactivate(c: *mut HlmFfiClient) -> c_int;
    /// Force-fetch a fresh signed license, ignoring the cache.
    pub fn hlm_ffi_refresh(c: *mut HlmFfiClient) -> c_int;

    /* State accessors — valid after a successful check/activate/refresh. */
    pub fn hlm_ffi_status(c: *mut HlmFfiClient) -> c_int;
    pub fn hlm_ffi_status_name(c: *mut HlmFfiClient) -> *const c_char;
    pub fn hlm_ffi_license_id(c: *mut HlmFfiClient) -> *const c_char;
    pub fn hlm_ffi_product_name(c: *mut HlmFfiClient) -> *const c_char;
    pub fn hlm_ffi_buyer_email(c: *mut HlmFfiClient) -> *const c_char;
    /// Unix seconds; `i64::MIN` = none.
    pub fn hlm_ffi_expires(c: *mut HlmFfiClient) -> i64;
    pub fn hlm_ffi_trial_end(c: *mut HlmFfiClient) -> i64;
    pub fn hlm_ffi_receipt_expires(c: *mut HlmFfiClient) -> i64;
    pub fn hlm_ffi_live_mode(c: *mut HlmFfiClient) -> c_int;
    pub fn hlm_ffi_metadata(c: *mut HlmFfiClient, key: *const c_char) -> *const c_char;
    pub fn hlm_ffi_last_http_status(c: *mut HlmFfiClient) -> c_int;

    /// The server's human-readable refusal detail from the last failed call
    /// on this client ("" when none).
    pub fn hlm_ffi_last_error_detail(c: *mut HlmFfiClient) -> *const c_char;

    /* Stateless helpers */
    pub fn hlm_ffi_err_name(err: c_int) -> *const c_char;
    /// Hardware fingerprint (Crockford Base32) into `out` (cap bytes).
    pub fn hlm_ffi_machine_id(out: *mut c_char, cap: c_int) -> c_int;
    pub fn hlm_ffi_machine_name(out: *mut c_char, cap: c_int) -> c_int;

    /// Offline one-shot: verify a signed license string against `jwks_json`
    /// and report its status at unix time `now` (0 = system clock).
    pub fn hlm_ffi_verify(
        jws: *const c_char,
        jwks_json: *const c_char,
        expected_product_id: *const c_char,
        expected_machine_id: *const c_char,
        now: i64,
        status_out: *mut c_int,
    ) -> c_int;
}
