/* SHA-512 (FIPS 180-4), same shape as hlm_sha256.c: streaming context,
 * no allocation, no OS calls. */
#include <string.h>

#include "hlm_sha512.h"

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void compress(hlm_sha512_ctx *c, const uint8_t block[128])
{
    uint64_t w[80];
    uint64_t a, b, d, e, f, g, h, t1, t2, s0, s1, ch, maj;
    uint64_t cc;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint64_t)block[i * 8] << 56) |
               ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) |
               ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) |
               ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8) |
               (uint64_t)block[i * 8 + 7];
    for (i = 16; i < 80; i++) {
        s0 = ROTR(w[i - 15], 1) ^ ROTR(w[i - 15], 8) ^ (w[i - 15] >> 7);
        s1 = ROTR(w[i - 2], 19) ^ ROTR(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];

    for (i = 0; i < 80; i++) {
        s1 = ROTR(e, 14) ^ ROTR(e, 18) ^ ROTR(e, 41);
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + K[i] + w[i];
        s0 = ROTR(a, 28) ^ ROTR(a, 34) ^ ROTR(a, 39);
        maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void hlm_sha512_init(hlm_sha512_ctx *c)
{
    c->state[0] = 0x6a09e667f3bcc908ULL;
    c->state[1] = 0xbb67ae8584caa73bULL;
    c->state[2] = 0x3c6ef372fe94f82bULL;
    c->state[3] = 0xa54ff53a5f1d36f1ULL;
    c->state[4] = 0x510e527fade682d1ULL;
    c->state[5] = 0x9b05688c2b3e6c1fULL;
    c->state[6] = 0x1f83d9abfb41bd6bULL;
    c->state[7] = 0x5be0cd19137e2179ULL;
    c->bitlen_hi = 0;
    c->bitlen_lo = 0;
    c->buf_len = 0;
}

void hlm_sha512_update(hlm_sha512_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint64_t add = (uint64_t)len << 3;

    c->bitlen_lo += add;
    if (c->bitlen_lo < add) c->bitlen_hi++;
    c->bitlen_hi += (uint64_t)len >> 61;

    if (c->buf_len > 0) {
        size_t take = 128 - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p += take;
        len -= take;
        if (c->buf_len == 128) {
            compress(c, c->buf);
            c->buf_len = 0;
        }
    }
    while (len >= 128) {
        compress(c, p);
        p += 128;
        len -= 128;
    }
    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }
}

void hlm_sha512_final(hlm_sha512_ctx *c, uint8_t out[64])
{
    uint64_t hi = c->bitlen_hi, lo = c->bitlen_lo;
    uint8_t pad = 0x80;
    uint8_t zero = 0;
    uint8_t lenb[16];
    int i;

    hlm_sha512_update(c, &pad, 1);
    while (c->buf_len != 112)
        hlm_sha512_update(c, &zero, 1);

    for (i = 0; i < 8; i++) lenb[i] = (uint8_t)(hi >> (56 - i * 8));
    for (i = 0; i < 8; i++) lenb[8 + i] = (uint8_t)(lo >> (56 - i * 8));
    /* bypass the length counter for the length block itself */
    memcpy(c->buf + c->buf_len, lenb, 16);
    compress(c, c->buf);

    for (i = 0; i < 8; i++) {
        out[i * 8] = (uint8_t)(c->state[i] >> 56);
        out[i * 8 + 1] = (uint8_t)(c->state[i] >> 48);
        out[i * 8 + 2] = (uint8_t)(c->state[i] >> 40);
        out[i * 8 + 3] = (uint8_t)(c->state[i] >> 32);
        out[i * 8 + 4] = (uint8_t)(c->state[i] >> 24);
        out[i * 8 + 5] = (uint8_t)(c->state[i] >> 16);
        out[i * 8 + 6] = (uint8_t)(c->state[i] >> 8);
        out[i * 8 + 7] = (uint8_t)c->state[i];
    }
}

void hlm_sha512(const void *data, size_t len, uint8_t out[64])
{
    hlm_sha512_ctx c;
    hlm_sha512_init(&c);
    hlm_sha512_update(&c, data, len);
    hlm_sha512_final(&c, out);
}
