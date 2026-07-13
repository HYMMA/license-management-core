/* Ed25519 (RFC 8032) signature verification — verify only, this library
 * never signs anything. */
#ifndef HLM_ED25519_H
#define HLM_ED25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verify a 64-byte Ed25519 signature over `msg` with the 32-byte public key.
 * Returns 1 valid, 0 invalid. Rejects non-canonical scalars (S >= L) and
 * public keys / R points that do not decode onto the curve. */
int hlm_ed25519_verify(const uint8_t pub[32],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig[64]);

#ifdef __cplusplus
}
#endif

#endif /* HLM_ED25519_H */
