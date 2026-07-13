/* SHA-512 (FIPS 180-4) — needed by the Ed25519 verifier. */
#ifndef HLM_SHA512_H
#define HLM_SHA512_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t state[8];
    uint64_t bitlen_hi, bitlen_lo;
    uint8_t buf[128];
    size_t buf_len;
} hlm_sha512_ctx;

void hlm_sha512_init(hlm_sha512_ctx *c);
void hlm_sha512_update(hlm_sha512_ctx *c, const void *data, size_t len);
void hlm_sha512_final(hlm_sha512_ctx *c, uint8_t out[64]);

void hlm_sha512(const void *data, size_t len, uint8_t out[64]);

#ifdef __cplusplus
}
#endif

#endif /* HLM_SHA512_H */
