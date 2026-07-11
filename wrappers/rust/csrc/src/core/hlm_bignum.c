#include "hlm_bignum.h"

#include <string.h>

/* ------------- raw limb helpers (explicit lengths, internal) ------------- */

/* out[an+bn] = a[an] * b[bn], schoolbook. out must not alias a/b. */
static void raw_mul(const uint32_t *a, int an, const uint32_t *b, int bn,
                    uint32_t *out)
{
    int i, j;
    memset(out, 0, (size_t)(an + bn) * sizeof(uint32_t));
    for (i = 0; i < an; i++) {
        uint64_t carry = 0;
        uint64_t ai = a[i];
        for (j = 0; j < bn; j++) {
            uint64_t t = ai * b[j] + out[i + j] + carry;
            out[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        out[i + bn] = (uint32_t)carry;
    }
}

static int raw_bitlen(const uint32_t *a, int an)
{
    int i;
    for (i = an - 1; i >= 0; i--) {
        if (a[i] != 0) {
            uint32_t x = a[i];
            int b = 0;
            while (x != 0) { x >>= 1; b++; }
            return i * 32 + b;
        }
    }
    return 0;
}

/* r has mn+1 limbs. Compare r (mn+1) with m (mn). */
static int raw_cmp_r_m(const uint32_t *r, const uint32_t *m, int mn)
{
    int i;
    if (r[mn] != 0) return 1;
    for (i = mn - 1; i >= 0; i--) {
        if (r[i] != m[i]) return r[i] > m[i] ? 1 : -1;
    }
    return 0;
}

/* r -= m over mn+1 limbs (m implicitly zero-extended). Requires r >= m. */
static void raw_sub_r_m(uint32_t *r, const uint32_t *m, int mn)
{
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < mn; i++) {
        uint64_t t = (uint64_t)r[i] - m[i] - borrow;
        r[i] = (uint32_t)t;
        borrow = (t >> 32) & 1;
    }
    r[mn] = (uint32_t)((uint64_t)r[mn] - borrow);
}

/* r[mn limbs] = num[numn limbs] mod m[mn limbs], binary long division.
 * Verification-only: not constant time, optimized for clarity. */
static void raw_mod(const uint32_t *num, int numn, const uint32_t *m, int mn,
                    uint32_t *r /* mn limbs out */)
{
    /* work buffer: mn+1 limbs */
    uint32_t w[HLM_BN_MAX_LIMBS + 1];
    int bits = raw_bitlen(num, numn);
    int i, j;

    memset(w, 0, (size_t)(mn + 1) * sizeof(uint32_t));

    for (i = bits - 1; i >= 0; i--) {
        /* w = (w << 1) | bit_i(num) */
        uint32_t carry = (num[i / 32] >> (i % 32)) & 1u;
        for (j = 0; j <= mn; j++) {
            uint32_t nc = w[j] >> 31;
            w[j] = (w[j] << 1) | carry;
            carry = nc;
        }
        if (raw_cmp_r_m(w, m, mn) >= 0) {
            raw_sub_r_m(w, m, mn);
        }
    }
    memcpy(r, w, (size_t)mn * sizeof(uint32_t));
}

/* ------------- hlm_bn wrappers ------------- */

static void bn_normalize(hlm_bn *a)
{
    while (a->n > 1 && a->v[a->n - 1] == 0) a->n--;
}

void hlm_bn_zero(hlm_bn *a)
{
    memset(a->v, 0, sizeof(a->v));
    a->n = 1;
}

void hlm_bn_from_u32(hlm_bn *a, uint32_t x)
{
    hlm_bn_zero(a);
    a->v[0] = x;
}

int hlm_bn_from_bytes_be(hlm_bn *a, const uint8_t *bytes, size_t len)
{
    size_t i;
    if (len > HLM_BN_MAX_LIMBS * 4) return -1;
    hlm_bn_zero(a);
    for (i = 0; i < len; i++) {
        size_t bit_index = (len - 1 - i) * 8;
        a->v[bit_index / 32] |= (uint32_t)bytes[i] << (bit_index % 32);
    }
    a->n = (int)((len + 3) / 4);
    if (a->n == 0) a->n = 1;
    bn_normalize(a);
    return 0;
}

int hlm_bn_to_bytes_be(const hlm_bn *a, uint8_t *bytes, size_t len)
{
    int bl = hlm_bn_bitlen(a);
    size_t need = (size_t)((bl + 7) / 8);
    size_t i;
    if (need > len) return -1;
    memset(bytes, 0, len);
    for (i = 0; i < need; i++) {
        size_t bit_index = i * 8;
        bytes[len - 1 - i] =
            (uint8_t)(a->v[bit_index / 32] >> (bit_index % 32));
    }
    return 0;
}

int hlm_bn_is_zero(const hlm_bn *a)
{
    int i;
    for (i = 0; i < a->n; i++) {
        if (a->v[i] != 0) return 0;
    }
    return 1;
}

int hlm_bn_cmp(const hlm_bn *a, const hlm_bn *b)
{
    int i;
    int an = a->n, bn = b->n;
    while (an > 1 && a->v[an - 1] == 0) an--;
    while (bn > 1 && b->v[bn - 1] == 0) bn--;
    if (an != bn) return an > bn ? 1 : -1;
    for (i = an - 1; i >= 0; i--) {
        if (a->v[i] != b->v[i]) return a->v[i] > b->v[i] ? 1 : -1;
    }
    return 0;
}

int hlm_bn_bitlen(const hlm_bn *a)
{
    return raw_bitlen(a->v, a->n);
}

int hlm_bn_bit(const hlm_bn *a, int i)
{
    if (i < 0 || i >= a->n * 32) return 0;
    return (int)((a->v[i / 32] >> (i % 32)) & 1u);
}

void hlm_bn_copy(hlm_bn *dst, const hlm_bn *src)
{
    memcpy(dst, src, sizeof(*dst));
}

int hlm_bn_add(hlm_bn *r, const hlm_bn *a, const hlm_bn *b)
{
    uint64_t carry = 0;
    int i;
    int n = a->n > b->n ? a->n : b->n;

    for (i = 0; i < n; i++) {
        uint64_t t = carry;
        if (i < a->n) t += a->v[i];
        if (i < b->n) t += b->v[i];
        r->v[i] = (uint32_t)t;
        carry = t >> 32;
    }
    if (carry != 0) {
        if (n >= HLM_BN_MAX_LIMBS) return -1;
        r->v[n++] = (uint32_t)carry;
    }
    for (i = n; i < HLM_BN_MAX_LIMBS; i++) r->v[i] = 0;
    r->n = n;
    bn_normalize(r);
    return 0;
}

void hlm_bn_sub(hlm_bn *r, const hlm_bn *a, const hlm_bn *b)
{
    uint64_t borrow = 0;
    int i;

    for (i = 0; i < a->n; i++) {
        uint64_t t = (uint64_t)a->v[i] - (i < b->n ? b->v[i] : 0) - borrow;
        r->v[i] = (uint32_t)t;
        borrow = (t >> 32) & 1;
    }
    for (i = a->n; i < HLM_BN_MAX_LIMBS; i++) r->v[i] = 0;
    r->n = a->n;
    bn_normalize(r);
}

void hlm_bn_mod(hlm_bn *r, const hlm_bn *a, const hlm_bn *m)
{
    uint32_t out[HLM_BN_MAX_LIMBS];
    int mn = m->n;
    raw_mod(a->v, a->n, m->v, mn, out);
    memset(r->v, 0, sizeof(r->v));
    memcpy(r->v, out, (size_t)mn * sizeof(uint32_t));
    r->n = mn;
    bn_normalize(r);
}

void hlm_bn_modadd(hlm_bn *r, const hlm_bn *a, const hlm_bn *b, const hlm_bn *m)
{
    /* a,b < m <= 4096 bits, so a+b fits (no capacity overflow for our uses) */
    hlm_bn t;
    hlm_bn_add(&t, a, b);
    if (hlm_bn_cmp(&t, m) >= 0) {
        hlm_bn_sub(&t, &t, m);
    }
    hlm_bn_copy(r, &t);
}

void hlm_bn_modsub(hlm_bn *r, const hlm_bn *a, const hlm_bn *b, const hlm_bn *m)
{
    hlm_bn t;
    if (hlm_bn_cmp(a, b) >= 0) {
        hlm_bn_sub(&t, a, b);
    } else {
        hlm_bn u;
        hlm_bn_sub(&u, m, b);   /* m - b */
        hlm_bn_add(&t, a, &u);  /* a + (m - b) < m + m; but a < m so < 2m */
        if (hlm_bn_cmp(&t, m) >= 0) hlm_bn_sub(&t, &t, m);
    }
    hlm_bn_copy(r, &t);
}

void hlm_bn_modmul(hlm_bn *r, const hlm_bn *a, const hlm_bn *b, const hlm_bn *m)
{
    uint32_t prod[2 * HLM_BN_MAX_LIMBS];
    uint32_t out[HLM_BN_MAX_LIMBS];
    int mn = m->n;

    raw_mul(a->v, a->n, b->v, b->n, prod);
    raw_mod(prod, a->n + b->n, m->v, mn, out);

    memset(r->v, 0, sizeof(r->v));
    memcpy(r->v, out, (size_t)mn * sizeof(uint32_t));
    r->n = mn;
    bn_normalize(r);
}

void hlm_bn_modexp(hlm_bn *r, const hlm_bn *base, const hlm_bn *exp, const hlm_bn *m)
{
    hlm_bn acc, b;
    int i, bits;

    hlm_bn_from_u32(&acc, 1);
    hlm_bn_mod(&b, base, m);

    bits = hlm_bn_bitlen(exp);
    for (i = bits - 1; i >= 0; i--) {
        hlm_bn_modmul(&acc, &acc, &acc, m);
        if (hlm_bn_bit(exp, i)) {
            hlm_bn_modmul(&acc, &acc, &b, m);
        }
    }
    hlm_bn_copy(r, &acc);
}
