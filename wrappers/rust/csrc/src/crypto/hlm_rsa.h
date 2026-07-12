/* RSASSA-PKCS1-v1_5 / SHA-256 signature VERIFICATION (RS256). Portable C99. */
#ifndef HLM_RSA_H
#define HLM_RSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verify `sig` (big-endian, same length as modulus) over `msg`.
 * Key is raw big-endian modulus + exponent (as delivered by a JWK's n/e).
 * Returns 1 = valid, 0 = invalid, <0 = bad input (key too large etc.). */
int hlm_rsa_pkcs1_sha256_verify(const uint8_t *modulus, size_t modulus_len,
                                const uint8_t *exponent, size_t exponent_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* HLM_RSA_H */
