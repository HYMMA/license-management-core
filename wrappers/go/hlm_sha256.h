/* SHA-256 (FIPS 180-4) — portable C99, verify-path only dependency-free primitive. */
#ifndef HLM_SHA256_H
#define HLM_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HLM_SHA256_DIGEST_SIZE 32
#define HLM_SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[HLM_SHA256_BLOCK_SIZE];
    size_t buffer_len;
} hlm_sha256_ctx;

void hlm_sha256_init(hlm_sha256_ctx *ctx);
void hlm_sha256_update(hlm_sha256_ctx *ctx, const void *data, size_t len);
void hlm_sha256_final(hlm_sha256_ctx *ctx, uint8_t digest[HLM_SHA256_DIGEST_SIZE]);

/* One-shot convenience. */
void hlm_sha256(const void *data, size_t len, uint8_t digest[HLM_SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* HLM_SHA256_H */
