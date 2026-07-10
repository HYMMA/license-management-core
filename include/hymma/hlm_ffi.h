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

#if defined(_WIN32) && defined(HLM_FFI_BUILD_DLL)
#define HLM_API __declspec(dllexport)
#else
#define HLM_API
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
 *  machine_id    NULL => derive from hardware (Windows builds)
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

/* Stateless helpers */
HLM_API const char *hlm_ffi_err_name(int err);
HLM_API int hlm_ffi_machine_id(char *out, int cap);   /* hardware fingerprint */
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
