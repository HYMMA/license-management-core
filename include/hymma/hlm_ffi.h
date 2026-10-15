/* Flat FFI surface for language wrappers (.NET P/Invoke, Python ctypes,
 * Java JNA, Node ffi-napi, Go cgo, ...).
 *
 * The core API in hymma/hlm.h is C-idiomatic (config structs, callback
 * ports) — great for C/C++/embedded, awkward across an FFI boundary.
 * This layer flattens it into an opaque handle plus plain functions with
 * string/int parameters, wired to the built-in desktop ports. Every
 * wrapper in every language binds to THESE symbols, so the licensing
 * behavior is implemented exactly once.
 *
 * Thread-safety: one handle per thread, or serialize calls yourself.
 * Returned strings are owned by the handle and valid until the next call
 * on that handle (or hlm_ffi_destroy).
 */
#ifndef HYMMA_LM_FFI_H
#define HYMMA_LM_FFI_H

#include <stdint.h>

/* Export annotation for the shared library. The CMake shared target
 * defines HLM_FFI_BUILD_DLL and compiles with hidden visibility, so ONLY
 * the hlm_ffi_* surface below is public ABI; internal helpers (hlm_bn_*,
 * hlm_sha256_*, JSON, ...) stay private. Static/embedded builds get no
 * annotation. */
#if defined(HLM_FFI_BUILD_DLL)
#  if defined(_WIN32)
#    define HLM_API __declspec(dllexport)
#  elif defined(__GNUC__)
#    define HLM_API __attribute__((visibility("default")))
#  else
#    define HLM_API
#  endif
#else
#  define HLM_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hlm_ffi_client hlm_ffi_client;

/* Create a client.
 *  base_url      NULL => https://license-management.com/api/
 *  product_id    required (PRD_...)
 *  client_api_key required (PUB_..., never MST_)
 *  jwks_json     required: one JWK object or a JSON array of JWKs
 *                (the vendor's public keys — from /api/signingkeys.json)
 *  format        1=RS256("jws") 2=ES256("es256") 3=EdDSA("eddsa")
 *  valid_days    0 => 90
 *  machine_id    NULL => identity v2 (MachineGuid) with the v1 hardware
 *                fingerprint sent as LegacyMacAddress for server re-key
 *                (Windows builds; v1 alone when no MachineGuid)
 *  machine_name  NULL => this computer's name (Windows builds)
 *  license_path  NULL => no offline cache; else the .lic cache file
 * Returns NULL on invalid arguments. */
HLM_API hlm_ffi_client *hlm_ffi_create(const char *base_url,
                                       const char *product_id,
                                       const char *client_api_key,
                                       const char *jwks_json,
                                       int format,
                                       unsigned valid_days,
                                       const char *machine_id,
                                       const char *machine_name,
                                       const char *license_path);

HLM_API void hlm_ffi_destroy(hlm_ffi_client *c);

/* Silent check & trial bootstrap. Returns 0 (HLM_OK) or an hlm_err. */
HLM_API int hlm_ffi_check(hlm_ffi_client *c);

/* Attach a purchased receipt code, then refresh. */
HLM_API int hlm_ffi_activate(hlm_ffi_client *c, const char *receipt_code);

/* Free this machine's seat (uninstall). */
HLM_API int hlm_ffi_deactivate(hlm_ffi_client *c);

/* Force-fetch a fresh signed license, ignoring the cache. */
HLM_API int hlm_ffi_refresh(hlm_ffi_client *c);

/* State accessors — valid after a successful check/activate/refresh. */
HLM_API int hlm_ffi_status(hlm_ffi_client *c);            /* hlm_status */
HLM_API const char *hlm_ffi_status_name(hlm_ffi_client *c);
HLM_API const char *hlm_ffi_license_id(hlm_ffi_client *c);
HLM_API const char *hlm_ffi_product_name(hlm_ffi_client *c);
HLM_API const char *hlm_ffi_buyer_email(hlm_ffi_client *c);
HLM_API int64_t hlm_ffi_expires(hlm_ffi_client *c);       /* unix; INT64_MIN=none */
HLM_API int64_t hlm_ffi_trial_end(hlm_ffi_client *c);
HLM_API int64_t hlm_ffi_receipt_expires(hlm_ffi_client *c);
HLM_API int hlm_ffi_live_mode(hlm_ffi_client *c);
HLM_API const char *hlm_ffi_metadata(hlm_ffi_client *c, const char *key);
HLM_API int hlm_ffi_last_http_status(hlm_ffi_client *c);

/* The human-readable detail of the last failed call on this client ("" when
 * none) — show it to the user alongside the error code: the server's refusal
 * detail, or for HLM_E_HTTP (-7) a message saying what failed and naming the
 * host to allow. After hlm_ffi_import_license*, the end-user message for the
 * import outcome (including "License file installed."). */
HLM_API const char *hlm_ffi_last_error_detail(hlm_ffi_client *c);

/* Why the server could not be reached on the last call (hlm_net_failure:
 * 0 None, 1 Unknown, 2 NameResolution, 3 SecureConnection, 4 Proxy,
 * 5 Timeout, 6 Connection). Also set when check() succeeded from the cached
 * file because the network failed — a UI can offer the by-hand install. */
HLM_API int hlm_ffi_last_network_failure(hlm_ffi_client *c);
HLM_API const char *hlm_ffi_network_failure_name(int failure);

/* Install a license file obtained outside the online flow (vendor portal,
 * email) for a computer that cannot reach the server. Verified exactly as
 * the offline cache is (signature with the vendor keys, product, this
 * machine under identity v2 or the legacy id) and only then written to
 * license_path; a file that fails verification never replaces the existing
 * one. Returns an hlm_import_result:
 *   0 Installed, 1 NotALicenseFile, 2 NoPublicKey, 3 SignatureInvalid,
 *   4 WrongProduct, 5 WrongComputer, 6 WriteFailed
 * or HLM_E_ARG (-1) for a NULL argument or a client created without
 * license_path. Never touches the network. */
HLM_API int hlm_ffi_import_license(hlm_ffi_client *c, const char *document);
/* Same, reading the document from `path` (an unreadable or oversized file
 * is NotALicenseFile, with the reason in hlm_ffi_last_error_detail). */
HLM_API int hlm_ffi_import_license_file(hlm_ffi_client *c, const char *path);
HLM_API const char *hlm_ffi_import_result_name(int result);

/* The license cache file this client reads and writes (the license_path it
 * was created with; "" when none) — read-only, for a host UI to show where
 * the license lives. */
HLM_API const char *hlm_ffi_license_path(hlm_ffi_client *c);

/* Stateless helpers */
HLM_API const char *hlm_ffi_err_name(int err);
HLM_API int hlm_ffi_machine_id(char *out, int cap);   /* v1 hardware fingerprint */
/* Identity v2: MachineGuid fingerprint on Windows (collision-proof);
 * on POSIX identical to hlm_ffi_machine_id(). */
HLM_API int hlm_ffi_machine_id_v2(char *out, int cap);
HLM_API int hlm_ffi_machine_name(char *out, int cap);

/* Offline one-shot: verify a signed license string against jwks_json and
 * report its status at unix time `now` (pass 0 for the system clock).
 * Returns HLM_OK and writes the status enum into *status_out. */
HLM_API int hlm_ffi_verify(const char *jws,
                           const char *jwks_json,
                           const char *expected_product_id,
                           const char *expected_machine_id,
                           int64_t now,
                           int *status_out);

#ifdef __cplusplus
}
#endif

#endif /* HYMMA_LM_FFI_H */
