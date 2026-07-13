/* Ed25519 verification, from scratch in portable C99 like hlm_rsa/hlm_p256.
 *
 * Field elements are 16 limbs of 16 bits (radix 2^16) held in int64_t, the
 * classic TweetNaCl representation: every intermediate fits comfortably in
 * 64 bits, so this builds with any C99 compiler (no __int128, MSVC included)
 * and runs on 32-bit MCUs. Verification only — no signing, no secret keys,
 * so side-channel pressure is low; comparisons still avoid data-dependent
 * branches where cheap.
 *
 * Beyond the classic verify this enforces RFC 8032 canonicality: S must be
 * < L (rejects signature malleability) and the public key and R must decode
 * onto the curve.
 */
#include <string.h>

#include "hlm_ed25519.h"
#include "hlm_sha512.h"

typedef int64_t gf[16];

static const gf GF0 = { 0 };
static const gf GF1 = { 1 };

/* d = -121665/121666 mod 2^255-19 */
static const gf ED_D = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141,
                         0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
                         0xfe73, 0x2b6f, 0x6cee, 0x5203 };
/* 2d */
static const gf ED_D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283,
                          0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
                          0xfce7, 0x56df, 0xd9dc, 0x2406 };
/* base point */
static const gf ED_X = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525,
                         0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
                         0x53fe, 0xcd6e, 0x36d3, 0x2169 };
static const gf ED_Y = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                         0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                         0x6666, 0x6666, 0x6666, 0x6666 };
/* sqrt(-1) */
static const gf ED_I = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f,
                         0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
                         0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

/* group order L = 2^252 + 27742317777372353535851937790883648493 (LE bytes) */
static const uint8_t ED_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* ------------------------------------------------------------------ */
/* field arithmetic mod 2^255-19                                       */
/* ------------------------------------------------------------------ */

static void fe_copy(gf r, const gf a)
{
    int i;
    for (i = 0; i < 16; i++) r[i] = a[i];
}

static void fe_carry(gf o)
{
    int i;
    int64_t c;
    for (i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536; /* not "c << 16": c can be negative, left-shift would be UB */
    }
}

/* constant-time: if b then swap contents of p and q (b in {0,1}) */
static void fe_sel(gf p, gf q, int b)
{
    int i;
    int64_t t, mask = ~(int64_t)(b - 1);
    for (i = 0; i < 16; i++) {
        t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void fe_pack(uint8_t *o, const gf n)
{
    int i, j, b;
    gf m, t;
    fe_copy(t, n);
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        fe_sel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void fe_unpack(gf o, const uint8_t *n)
{
    int i;
    for (i = 0; i < 16; i++)
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

/* 1 if a != b (mod p), 0 if equal */
static int fe_neq(const gf a, const gf b)
{
    uint8_t x[32], y[32];
    uint32_t d = 0;
    int i;
    fe_pack(x, a);
    fe_pack(y, b);
    for (i = 0; i < 32; i++) d |= (uint32_t)(x[i] ^ y[i]);
    return (int)((d | (0u - d)) >> 31);
}

/* low bit of the canonical form (the "sign" of x) */
static int fe_parity(const gf a)
{
    uint8_t d[32];
    fe_pack(d, a);
    return d[0] & 1;
}

static void fe_add(gf o, const gf a, const gf b)
{
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void fe_sub(gf o, const gf a, const gf b)
{
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void fe_mul(gf o, const gf a, const gf b)
{
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    fe_carry(o);
    fe_carry(o);
}

static void fe_sq(gf o, const gf a)
{
    fe_mul(o, a, a);
}

/* a^(p-2): inverse */
static void fe_inv(gf o, const gf i)
{
    gf c;
    int a;
    fe_copy(c, i);
    for (a = 253; a >= 0; a--) {
        fe_sq(c, c);
        if (a != 2 && a != 4) fe_mul(c, c, i);
    }
    fe_copy(o, c);
}

/* a^((p-5)/8): used for the square root in point decompression */
static void fe_pow2523(gf o, const gf i)
{
    gf c;
    int a;
    fe_copy(c, i);
    for (a = 250; a >= 0; a--) {
        fe_sq(c, c);
        if (a != 1) fe_mul(c, c, i);
    }
    fe_copy(o, c);
}

/* ------------------------------------------------------------------ */
/* group operations (extended twisted Edwards coordinates X,Y,Z,T)     */
/* ------------------------------------------------------------------ */

static void point_add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;

    fe_sub(a, p[1], p[0]);
    fe_sub(t, q[1], q[0]);
    fe_mul(a, a, t);
    fe_add(b, p[0], p[1]);
    fe_add(t, q[0], q[1]);
    fe_mul(b, b, t);
    fe_mul(c, p[3], q[3]);
    fe_mul(c, c, ED_D2);
    fe_mul(d, p[2], q[2]);
    fe_add(d, d, d);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);

    fe_mul(p[0], e, f);
    fe_mul(p[1], h, g);
    fe_mul(p[2], g, f);
    fe_mul(p[3], e, h);
}

static void point_cswap(gf p[4], gf q[4], int b)
{
    int i;
    for (i = 0; i < 4; i++) fe_sel(p[i], q[i], b);
}

static void point_pack(uint8_t *r, gf p[4])
{
    gf tx, ty, zi;
    fe_inv(zi, p[2]);
    fe_mul(tx, p[0], zi);
    fe_mul(ty, p[1], zi);
    fe_pack(r, ty);
    r[31] ^= (uint8_t)(fe_parity(tx) << 7);
}

/* p = s*q (consumes q; ladder is branch-free) */
static void point_scalarmult(gf p[4], gf q[4], const uint8_t *s)
{
    int i;
    fe_copy(p[0], GF0);
    fe_copy(p[1], GF1);
    fe_copy(p[2], GF1);
    fe_copy(p[3], GF0);
    for (i = 255; i >= 0; --i) {
        int b = (s[i / 8] >> (i & 7)) & 1;
        point_cswap(p, q, b);
        point_add(q, p);
        point_add(p, p);
        point_cswap(p, q, b);
    }
}

static void point_scalarbase(gf p[4], const uint8_t *s)
{
    gf q[4];
    fe_copy(q[0], ED_X);
    fe_copy(q[1], ED_Y);
    fe_copy(q[2], GF1);
    fe_mul(q[3], ED_X, ED_Y);
    point_scalarmult(p, q, s);
}

/* Decompress a point encoding into (X,Y,Z,T) with X negated — verification
 * needs -A anyway, so decode straight to the negative like TweetNaCl does.
 * Returns 0 ok, -1 if the encoding is not on the curve. */
static int point_unpack_neg(gf r[4], const uint8_t p[32])
{
    gf t, chk, num, den, den2, den4, den6;

    fe_copy(r[2], GF1);
    fe_unpack(r[1], p);

    /* num = y^2 - 1, den = d*y^2 + 1 */
    fe_sq(num, r[1]);
    fe_mul(den, num, ED_D);
    fe_sub(num, num, r[2]);
    fe_add(den, r[2], den);

    /* x = num^3 * den * (num^7 * den^7)^((p-5)/8) / ... — standard trick */
    fe_sq(den2, den);
    fe_sq(den4, den2);
    fe_mul(den6, den4, den2);
    fe_mul(t, den6, num);
    fe_mul(t, t, den);

    fe_pow2523(t, t);
    fe_mul(t, t, num);
    fe_mul(t, t, den);
    fe_mul(t, t, den);
    fe_mul(r[0], t, den);

    fe_sq(chk, r[0]);
    fe_mul(chk, chk, den);
    if (fe_neq(chk, num)) fe_mul(r[0], r[0], ED_I);

    fe_sq(chk, r[0]);
    fe_mul(chk, chk, den);
    if (fe_neq(chk, num)) return -1;

    if (fe_parity(r[0]) == (p[31] >> 7)) fe_sub(r[0], GF0, r[0]);

    fe_mul(r[3], r[0], r[1]);
    return 0;
}

/* ------------------------------------------------------------------ */
/* scalar arithmetic mod L                                             */
/* ------------------------------------------------------------------ */

static void scalar_modL(uint8_t *r, int64_t x[64])
{
    int64_t carry;
    int i, j;

    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * ED_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256; /* not "carry << 8": carry can be negative, left-shift would be UB */
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * ED_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * ED_L[j];
    for (i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

/* reduce a 64-byte little-endian value mod L into its first 32 bytes */
static void scalar_reduce64(uint8_t r[64])
{
    int64_t x[64];
    int i;
    for (i = 0; i < 64; i++) x[i] = r[i];
    scalar_modL(r, x);
    for (i = 32; i < 64; i++) r[i] = 0;
}

/* 1 if s (32 bytes LE) < L, else 0 — rejects malleable signatures */
static int scalar_is_canonical(const uint8_t s[32])
{
    int i;
    for (i = 31; i >= 0; i--) {
        if (s[i] < ED_L[i]) return 1;
        if (s[i] > ED_L[i]) return 0;
    }
    return 0; /* s == L */
}

/* ------------------------------------------------------------------ */
/* verify                                                              */
/* ------------------------------------------------------------------ */

int hlm_ed25519_verify(const uint8_t pub[32],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig[64])
{
    gf p[4], q[4];
    hlm_sha512_ctx sc;
    uint8_t h[64], rcheck[32];
    uint32_t d = 0;
    int i;

    if (pub == NULL || sig == NULL || (msg == NULL && msg_len != 0))
        return 0;

    if (!scalar_is_canonical(sig + 32)) return 0;
    if (point_unpack_neg(q, pub) != 0) return 0;

    /* h = SHA-512(R || A || M) mod L */
    hlm_sha512_init(&sc);
    hlm_sha512_update(&sc, sig, 32);
    hlm_sha512_update(&sc, pub, 32);
    if (msg_len > 0) hlm_sha512_update(&sc, msg, msg_len);
    hlm_sha512_final(&sc, h);
    scalar_reduce64(h);

    /* R' = S*B + h*(-A); valid iff R' == R */
    point_scalarmult(p, q, h);
    point_scalarbase(q, sig + 32);
    point_add(p, q);
    point_pack(rcheck, p);

    for (i = 0; i < 32; i++) d |= (uint32_t)(rcheck[i] ^ sig[i]);
    return d == 0;
}
