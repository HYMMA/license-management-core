#include "hlm_b64url.h"

static const char ENC[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* -1 = invalid, -2 = padding */
static int dec_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    if (c == '=') return -2;
    return -1;
}

size_t hlm_b64url_decoded_size(size_t len)
{
    size_t rem = len % 4;
    if (rem == 1) return (size_t)-1;
    return (len / 4) * 3 + (rem == 2 ? 1 : rem == 3 ? 2 : 0);
}

size_t hlm_b64url_decode(const char *in, size_t len, uint8_t *out, size_t out_cap)
{
    size_t written = 0;
    uint32_t acc = 0;
    int bits = 0;
    size_t i;

    /* Trim tolerated '=' padding. */
    while (len > 0 && in[len - 1] == '=') len--;

    if (hlm_b64url_decoded_size(len) == (size_t)-1) return (size_t)-1;

    for (i = 0; i < len; i++) {
        int v = dec_val(in[i]);
        if (v < 0) return (size_t)-1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (written >= out_cap) return (size_t)-1;
            out[written++] = (uint8_t)((acc >> bits) & 0xffu);
        }
    }

    /* Reject non-canonical trailing bits (RFC 4648 §3.5 strictness). */
    if (bits > 0 && (acc & ((1u << bits) - 1u)) != 0) return (size_t)-1;

    return written;
}

size_t hlm_b64url_encoded_size(size_t len)
{
    return (len / 3) * 4 + (len % 3 == 1 ? 2 : len % 3 == 2 ? 3 : 0);
}

size_t hlm_b64url_encode(const uint8_t *in, size_t len, char *out, size_t out_cap)
{
    size_t need = hlm_b64url_encoded_size(len);
    size_t o = 0, i = 0;

    if (out_cap < need + 1) return (size_t)-1;

    while (len - i >= 3) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = ENC[(n >> 18) & 63];
        out[o++] = ENC[(n >> 12) & 63];
        out[o++] = ENC[(n >> 6) & 63];
        out[o++] = ENC[n & 63];
        i += 3;
    }
    if (len - i == 1) {
        uint32_t n = (uint32_t)in[i] << 16;
        out[o++] = ENC[(n >> 18) & 63];
        out[o++] = ENC[(n >> 12) & 63];
    } else if (len - i == 2) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = ENC[(n >> 18) & 63];
        out[o++] = ENC[(n >> 12) & 63];
        out[o++] = ENC[(n >> 6) & 63];
    }
    out[o] = '\0';
    return o;
}
