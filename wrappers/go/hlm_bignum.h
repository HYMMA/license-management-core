/* Fixed-capacity big-number arithmetic for SIGNATURE VERIFICATION ONLY.
 *
 * Public-key verification handles no secrets, so this code optimizes for
 * portability and reviewability, not constant-time execution or speed.
 * 32-bit limbs with 64-bit intermediates — runs on anything from MSVC x64
 * down to a Cortex-M0.
 */
#ifndef HLM_BIGNUM_H
#define HLM_BIGNUM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 4096-bit ceiling: RSA-4096 moduli; P-256 uses 8 limbs of it. */
#define HLM_BN_MAX_LIMBS 128

typedef struct {
    uint32_t v[HLM_BN_MAX_LIMBS]; /* little-endian limbs */
    int n;                        /* significant limb count (>=1) */
} hlm_bn;

void hlm_bn_zero(hlm_bn *a);
void hlm_bn_from_u32(hlm_bn *a, uint32_t x);
int hlm_bn_from_bytes_be(hlm_bn *a, const uint8_t *bytes, size_t len);
/* Writes exactly `len` bytes big-endian (left-padded with zeros).
 * Returns -1 if the value does not fit. */
int hlm_bn_to_bytes_be(const hlm_bn *a, uint8_t *bytes, size_t len);

int hlm_bn_is_zero(const hlm_bn *a);
int hlm_bn_cmp(const hlm_bn *a, const hlm_bn *b); /* -1, 0, 1 */
int hlm_bn_bitlen(const hlm_bn *a);
int hlm_bn_bit(const hlm_bn *a, int i); /* 0 or 1 */

void hlm_bn_copy(hlm_bn *dst, const hlm_bn *src);

/* r = a + b. Returns -1 on overflow of capacity. */
int hlm_bn_add(hlm_bn *r, const hlm_bn *a, const hlm_bn *b);
/* r = a - b; requires a >= b. */
void hlm_bn_sub(hlm_bn *r, const hlm_bn *a, const hlm_bn *b);

/* r = a mod m (binary long division; a may be up to 2x m's width). */
void hlm_bn_mod(hlm_bn *r, const hlm_bn *a, const hlm_bn *m);

/* r = (a + b) mod m — a,b already < m. */
void hlm_bn_modadd(hlm_bn *r, const hlm_bn *a, const hlm_bn *b, const hlm_bn *m);
/* r = (a - b) mod m — a,b already < m. */
void hlm_bn_modsub(hlm_bn *r, const hlm_bn *a, const hlm_bn *b, const hlm_bn *m);
/* r = (a * b) mod m — a,b already < m. Requires m->n <= HLM_BN_MAX_LIMBS/2. */
void hlm_bn_modmul(hlm_bn *r, const hlm_bn *a, const hlm_bn *b, const hlm_bn *m);
/* r = base^exp mod m. Requires m->n <= HLM_BN_MAX_LIMBS/2, m odd or even. */
void hlm_bn_modexp(hlm_bn *r, const hlm_bn *base, const hlm_bn *exp, const hlm_bn *m);

#ifdef __cplusplus
}
#endif

#endif /* HLM_BIGNUM_H */
