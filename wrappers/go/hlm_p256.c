/* ECDSA P-256 verification over the generic hlm_bn engine.
 *
 * Point arithmetic uses Jacobian coordinates with the a = -3 doubling
 * (EFD dbl-2001-b) and general addition (EFD add-1998-cmo-2). Speed is
 * deliberately traded for reviewability; a license is verified once per
 * launch, not in a hot loop.
 */
#include "hlm_p256.h"

#include <string.h>

#include "hlm_bignum.h"
#include "hlm_sha256.h"

/* NIST P-256 domain parameters (SEC 2 / FIPS 186-4), big-endian. */
static const uint8_t P256_P[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const uint8_t P256_N[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
static const uint8_t P256_B[32] = {
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55,
    0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
    0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
};
static const uint8_t P256_GX[32] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5,
    0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};
static const uint8_t P256_GY[32] = {
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
    0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

typedef struct {
    hlm_bn x, y, z; /* Jacobian; infinity <=> z == 0 */
} jpoint;

typedef struct {
    hlm_bn p, n, b, gx, gy;
} p256_ctx;

static void ctx_init(p256_ctx *c)
{
    hlm_bn_from_bytes_be(&c->p, P256_P, 32);
    hlm_bn_from_bytes_be(&c->n, P256_N, 32);
    hlm_bn_from_bytes_be(&c->b, P256_B, 32);
    hlm_bn_from_bytes_be(&c->gx, P256_GX, 32);
    hlm_bn_from_bytes_be(&c->gy, P256_GY, 32);
}

static void jp_set_infinity(jpoint *r)
{
    hlm_bn_from_u32(&r->x, 1);
    hlm_bn_from_u32(&r->y, 1);
    hlm_bn_zero(&r->z);
}

static int jp_is_infinity(const jpoint *a)
{
    return hlm_bn_is_zero(&a->z);
}

static void jp_from_affine(jpoint *r, const hlm_bn *x, const hlm_bn *y)
{
    hlm_bn_copy(&r->x, x);
    hlm_bn_copy(&r->y, y);
    hlm_bn_from_u32(&r->z, 1);
}

/* r = 2*a  (dbl-2001-b, a = -3) */
static void jp_double(const p256_ctx *c, jpoint *r, const jpoint *a)
{
    hlm_bn delta, gamma, beta, alpha, t1, t2, t3;

    if (jp_is_infinity(a) || hlm_bn_is_zero(&a->y)) {
        jp_set_infinity(r);
        return;
    }

    hlm_bn_modmul(&delta, &a->z, &a->z, &c->p);         /* delta = Z1^2 */
    hlm_bn_modmul(&gamma, &a->y, &a->y, &c->p);         /* gamma = Y1^2 */
    hlm_bn_modmul(&beta, &a->x, &gamma, &c->p);         /* beta = X1*gamma */

    hlm_bn_modsub(&t1, &a->x, &delta, &c->p);           /* X1 - delta */
    hlm_bn_modadd(&t2, &a->x, &delta, &c->p);           /* X1 + delta */
    hlm_bn_modmul(&t1, &t1, &t2, &c->p);
    hlm_bn_modadd(&t2, &t1, &t1, &c->p);
    hlm_bn_modadd(&alpha, &t2, &t1, &c->p);             /* alpha = 3*(X1-d)(X1+d) */

    hlm_bn_modmul(&t1, &alpha, &alpha, &c->p);          /* alpha^2 */
    hlm_bn_modadd(&t2, &beta, &beta, &c->p);            /* 2beta */
    hlm_bn_modadd(&t2, &t2, &t2, &c->p);                /* 4beta */
    hlm_bn_modadd(&t3, &t2, &t2, &c->p);                /* 8beta */
    hlm_bn_modsub(&t1, &t1, &t3, &c->p);                /* X3 = alpha^2 - 8beta */

    /* Z3 = (Y1+Z1)^2 - gamma - delta */
    hlm_bn_modadd(&t3, &a->y, &a->z, &c->p);
    hlm_bn_modmul(&t3, &t3, &t3, &c->p);
    hlm_bn_modsub(&t3, &t3, &gamma, &c->p);
    hlm_bn_modsub(&t3, &t3, &delta, &c->p);

    /* Y3 = alpha*(4beta - X3) - 8*gamma^2 */
    hlm_bn_modsub(&t2, &t2, &t1, &c->p);                /* 4beta - X3 */
    hlm_bn_modmul(&t2, &alpha, &t2, &c->p);
    hlm_bn_modmul(&gamma, &gamma, &gamma, &c->p);       /* gamma^2 */
    {
        hlm_bn g2;
        hlm_bn_modadd(&g2, &gamma, &gamma, &c->p);      /* 2 */
        hlm_bn_modadd(&g2, &g2, &g2, &c->p);            /* 4 */
        hlm_bn_modadd(&g2, &g2, &g2, &c->p);            /* 8*gamma^2 */
        hlm_bn_modsub(&t2, &t2, &g2, &c->p);
    }

    hlm_bn_copy(&r->x, &t1);
    hlm_bn_copy(&r->y, &t2);
    hlm_bn_copy(&r->z, &t3);
}

/* r = a + b  (add-1998-cmo-2, general Jacobian) */
static void jp_add(const p256_ctx *c, jpoint *r, const jpoint *a, const jpoint *b)
{
    hlm_bn z1z1, z2z2, u1, u2, s1, s2, h, rr, hh, hhh, t1, t2;

    if (jp_is_infinity(a)) { *r = *b; return; }
    if (jp_is_infinity(b)) { *r = *a; return; }

    hlm_bn_modmul(&z1z1, &a->z, &a->z, &c->p);
    hlm_bn_modmul(&z2z2, &b->z, &b->z, &c->p);
    hlm_bn_modmul(&u1, &a->x, &z2z2, &c->p);
    hlm_bn_modmul(&u2, &b->x, &z1z1, &c->p);

    hlm_bn_modmul(&s1, &b->z, &z2z2, &c->p);            /* Z2^3 */
    hlm_bn_modmul(&s1, &a->y, &s1, &c->p);              /* S1 = Y1*Z2^3 */
    hlm_bn_modmul(&s2, &a->z, &z1z1, &c->p);            /* Z1^3 */
    hlm_bn_modmul(&s2, &b->y, &s2, &c->p);              /* S2 = Y2*Z1^3 */

    if (hlm_bn_cmp(&u1, &u2) == 0) {
        if (hlm_bn_cmp(&s1, &s2) != 0) {
            jp_set_infinity(r);
        } else {
            jp_double(c, r, a);
        }
        return;
    }

    hlm_bn_modsub(&h, &u2, &u1, &c->p);                 /* H = U2-U1 */
    hlm_bn_modsub(&rr, &s2, &s1, &c->p);                /* R = S2-S1 */
    hlm_bn_modmul(&hh, &h, &h, &c->p);                  /* H^2 */
    hlm_bn_modmul(&hhh, &h, &hh, &c->p);                /* H^3 */
    hlm_bn_modmul(&t1, &u1, &hh, &c->p);                /* U1*H^2 */

    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    hlm_bn_modmul(&t2, &rr, &rr, &c->p);
    hlm_bn_modsub(&t2, &t2, &hhh, &c->p);
    hlm_bn_modsub(&t2, &t2, &t1, &c->p);
    hlm_bn_modsub(&t2, &t2, &t1, &c->p);
    hlm_bn_copy(&r->x, &t2);

    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    hlm_bn_modsub(&t1, &t1, &r->x, &c->p);
    hlm_bn_modmul(&t1, &rr, &t1, &c->p);
    hlm_bn_modmul(&t2, &s1, &hhh, &c->p);
    hlm_bn_modsub(&r->y, &t1, &t2, &c->p);

    /* Z3 = Z1*Z2*H */
    hlm_bn_modmul(&t1, &a->z, &b->z, &c->p);
    hlm_bn_modmul(&r->z, &t1, &h, &c->p);
}

/* r = k * a, plain MSB-first double-and-add (verification: not secret-dependent-hardened) */
static void jp_scalar_mul(const p256_ctx *c, jpoint *r, const hlm_bn *k,
                          const jpoint *a)
{
    int i, bits = hlm_bn_bitlen(k);
    jpoint acc;

    jp_set_infinity(&acc);
    for (i = bits - 1; i >= 0; i--) {
        jpoint t;
        jp_double(c, &t, &acc);
        if (hlm_bn_bit(k, i)) {
            jp_add(c, &acc, &t, a);
        } else {
            acc = t;
        }
    }
    *r = acc;
}

/* out = a^-1 mod m for prime m, via Fermat: a^(m-2) mod m. */
static void bn_mod_inverse_fermat(hlm_bn *out, const hlm_bn *a, const hlm_bn *m)
{
    hlm_bn mm2, two;
    hlm_bn_from_u32(&two, 2);
    hlm_bn_sub(&mm2, m, &two);
    hlm_bn_modexp(out, a, &mm2, m);
}

/* x_affine = X / Z^2 mod p (via Fermat inverse). Returns 0 for infinity. */
static int jp_affine_x(const p256_ctx *c, hlm_bn *out, const jpoint *a)
{
    hlm_bn zinv, zinv2;

    if (jp_is_infinity(a)) return 0;

    bn_mod_inverse_fermat(&zinv, &a->z, &c->p);         /* Z^-1 */
    hlm_bn_modmul(&zinv2, &zinv, &zinv, &c->p);         /* Z^-2 */
    hlm_bn_modmul(out, &a->x, &zinv2, &c->p);
    return 1;
}

/* y^2 == x^3 - 3x + b (mod p) */
static int on_curve(const p256_ctx *c, const hlm_bn *x, const hlm_bn *y)
{
    hlm_bn lhs, rhs, t;

    hlm_bn_modmul(&lhs, y, y, &c->p);

    hlm_bn_modmul(&rhs, x, x, &c->p);
    hlm_bn_modmul(&rhs, &rhs, x, &c->p);                /* x^3 */
    hlm_bn_modadd(&t, x, x, &c->p);
    hlm_bn_modadd(&t, &t, x, &c->p);                    /* 3x */
    hlm_bn_modsub(&rhs, &rhs, &t, &c->p);
    hlm_bn_modadd(&rhs, &rhs, &c->b, &c->p);

    return hlm_bn_cmp(&lhs, &rhs) == 0;
}

int hlm_p256_ecdsa_sha256_verify(const uint8_t qx[32], const uint8_t qy[32],
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t sig[64])
{
    p256_ctx c;
    hlm_bn x, y, r, s, e, w, u1, u2, v;
    jpoint q, g, p1, p2, sum;
    uint8_t digest[HLM_SHA256_DIGEST_SIZE];

    ctx_init(&c);

    hlm_bn_from_bytes_be(&x, qx, 32);
    hlm_bn_from_bytes_be(&y, qy, 32);
    hlm_bn_from_bytes_be(&r, sig, 32);
    hlm_bn_from_bytes_be(&s, sig + 32, 32);

    /* public key sanity: coordinates in field, point on curve, not infinity */
    if (hlm_bn_cmp(&x, &c.p) >= 0 || hlm_bn_cmp(&y, &c.p) >= 0) return -1;
    if (hlm_bn_is_zero(&x) && hlm_bn_is_zero(&y)) return -1;
    if (!on_curve(&c, &x, &y)) return -1;

    /* r, s in [1, n-1] */
    if (hlm_bn_is_zero(&r) || hlm_bn_is_zero(&s)) return 0;
    if (hlm_bn_cmp(&r, &c.n) >= 0 || hlm_bn_cmp(&s, &c.n) >= 0) return 0;

    /* e = H(msg) mod n */
    hlm_sha256(msg, msg_len, digest);
    hlm_bn_from_bytes_be(&e, digest, 32);
    hlm_bn_mod(&e, &e, &c.n);

    /* w = s^-1 mod n (Fermat: n is prime) */
    bn_mod_inverse_fermat(&w, &s, &c.n);

    hlm_bn_modmul(&u1, &e, &w, &c.n);
    hlm_bn_modmul(&u2, &r, &w, &c.n);

    jp_from_affine(&q, &x, &y);
    jp_from_affine(&g, &c.gx, &c.gy);

    jp_scalar_mul(&c, &p1, &u1, &g);
    jp_scalar_mul(&c, &p2, &u2, &q);
    jp_add(&c, &sum, &p1, &p2);

    if (!jp_affine_x(&c, &v, &sum)) return 0;
    hlm_bn_mod(&v, &v, &c.n);

    return hlm_bn_cmp(&v, &r) == 0 ? 1 : 0;
}
