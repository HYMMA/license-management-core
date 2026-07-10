/* Base64url (RFC 4648 §5, no padding) — the JWS alphabet. Portable C99. */
#ifndef HLM_B64URL_H
#define HLM_B64URL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Exact decoded size for an unpadded base64url string of length `len`.
 * Returns (size_t)-1 if `len` is an impossible base64 length (4k+1). */
size_t hlm_b64url_decoded_size(size_t len);

/* Decode unpadded base64url (trailing '=' padding is tolerated).
 * Returns the number of bytes written, or (size_t)-1 on invalid input
 * or if `out_cap` is too small. */
size_t hlm_b64url_decode(const char *in, size_t len, uint8_t *out, size_t out_cap);

/* Encoded size (without NUL) for `len` input bytes, unpadded. */
size_t hlm_b64url_encoded_size(size_t len);

/* Encode to unpadded base64url. Writes a trailing NUL.
 * Returns chars written (excluding NUL), or (size_t)-1 if out_cap < encoded_size+1. */
size_t hlm_b64url_encode(const uint8_t *in, size_t len, char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* HLM_B64URL_H */
