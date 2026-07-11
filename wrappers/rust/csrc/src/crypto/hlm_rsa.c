#include "hlm_rsa.h"

#include <string.h>

#include "hlm_bignum.h"
#include "hlm_sha256.h"

/* DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note 1). */
static const uint8_t SHA256_DIGEST_INFO[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

int hlm_rsa_pkcs1_sha256_verify(const uint8_t *modulus, size_t modulus_len,
                                const uint8_t *exponent, size_t exponent_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len)
{
    hlm_bn n, e, s, em;
    uint8_t embytes[HLM_BN_MAX_LIMBS * 4];
    uint8_t digest[HLM_SHA256_DIGEST_SIZE];
    size_t k, i, ps_len;

    /* strip leading zeros of the modulus for a meaningful length check */
    while (modulus_len > 0 && modulus[0] == 0) { modulus++; modulus_len--; }
    k = modulus_len;
    if (k < 256 / 8 || k > HLM_BN_MAX_LIMBS * 4) return -1; /* < RSA-256? reject */
    if (sig_len != k) return 0;

    if (hlm_bn_from_bytes_be(&n, modulus, modulus_len) < 0) return -1;
    if (hlm_bn_from_bytes_be(&e, exponent, exponent_len) < 0) return -1;
    if (hlm_bn_from_bytes_be(&s, sig, sig_len) < 0) return -1;
    if (hlm_bn_is_zero(&n) || hlm_bn_is_zero(&e)) return -1;
    if (hlm_bn_cmp(&s, &n) >= 0) return 0;

    /* em = s^e mod n */
    hlm_bn_modexp(&em, &s, &e, &n);
    if (hlm_bn_to_bytes_be(&em, embytes, k) < 0) return 0;

    /* EM = 0x00 || 0x01 || PS(0xff..) || 0x00 || DigestInfo || H(msg) */
    if (k < 3 + 8 + sizeof(SHA256_DIGEST_INFO) + HLM_SHA256_DIGEST_SIZE) return 0;
    if (embytes[0] != 0x00 || embytes[1] != 0x01) return 0;

    ps_len = k - 3 - sizeof(SHA256_DIGEST_INFO) - HLM_SHA256_DIGEST_SIZE;
    if (ps_len < 8) return 0;
    for (i = 2; i < 2 + ps_len; i++) {
        if (embytes[i] != 0xff) return 0;
    }
    if (embytes[2 + ps_len] != 0x00) return 0;

    if (memcmp(embytes + 3 + ps_len, SHA256_DIGEST_INFO,
               sizeof(SHA256_DIGEST_INFO)) != 0)
        return 0;

    hlm_sha256(msg, msg_len, digest);
    if (memcmp(embytes + 3 + ps_len + sizeof(SHA256_DIGEST_INFO), digest,
               HLM_SHA256_DIGEST_SIZE) != 0)
        return 0;

    return 1;
}
