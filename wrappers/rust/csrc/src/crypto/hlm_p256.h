/* ECDSA P-256 / SHA-256 signature VERIFICATION (ES256). Portable C99.
 * Verification only — no private keys, no RNG, no constant-time requirement. */
#ifndef HLM_P256_H
#define HLM_P256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verify an IEEE P1363 signature (r||s, 64 bytes — the JWS ES256 layout)
 * over `msg` with public key point (qx, qy), each coordinate 32 bytes BE
 * (a JWK's x/y decode straight into this).
 * Returns 1 = valid, 0 = invalid, <0 = malformed input. */
int hlm_p256_ecdsa_sha256_verify(const uint8_t qx[32], const uint8_t qy[32],
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t sig[64]);

#ifdef __cplusplus
}
#endif

#endif /* HLM_P256_H */
