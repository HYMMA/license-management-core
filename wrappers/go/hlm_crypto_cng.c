/* Windows CNG (bcrypt) crypto backend — RS256 + ES256 via the OS.
 * EdDSA delegates to the portable Ed25519 verifier: CNG has no Ed25519
 * support, and apps that pick this backend should still verify every
 * format the server signs. */
#if defined(_WIN32)

#include <windows.h>
#include <bcrypt.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "hymma/hlm.h"
#include "hlm_ed25519.h"
#include "hlm_sha256.h"

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* SHA-256 of msg via CNG (keeps this backend self-contained). */
static NTSTATUS cng_sha256(const uint8_t *msg, size_t msg_len,
                           UCHAR out[HLM_SHA256_DIGEST_SIZE])
{
    BCRYPT_ALG_HANDLE halg = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&halg, BCRYPT_SHA256_ALGORITHM,
                                              NULL, 0);
    if (!NT_SUCCESS(st)) return st;
    st = BCryptHash(halg, NULL, 0, (PUCHAR)msg, (ULONG)msg_len, out,
                    HLM_SHA256_DIGEST_SIZE);
    BCryptCloseAlgorithmProvider(halg, 0);
    return st;
}

static int cng_verify_rsa(const hlm_public_key *key,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS st;
    int result = 0;
    UCHAR hash[HLM_SHA256_DIGEST_SIZE];
    DWORD hash_len = 0;
    BCRYPT_PKCS1_PADDING_INFO pad;
    UCHAR blob[8192];
    BCRYPT_RSAKEY_BLOB hdr;
    size_t blob_len;

    /* Build a BCRYPT_RSAPUBLIC_BLOB: header | exponent | modulus.
     * The header is built in a real struct and memcpy'd in — casting the
     * UCHAR buffer to BCRYPT_RSAKEY_BLOB* would violate alignment and
     * effective-type rules. */
    blob_len = sizeof(hdr) + key->u.rsa.e_len + key->u.rsa.n_len;
    if (blob_len > sizeof(blob)) return HLM_E_ARG;
    hdr.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    hdr.BitLength = (ULONG)(key->u.rsa.n_len * 8);
    hdr.cbPublicExp = (ULONG)key->u.rsa.e_len;
    hdr.cbModulus = (ULONG)key->u.rsa.n_len;
    hdr.cbPrime1 = 0;
    hdr.cbPrime2 = 0;
    memcpy(blob, &hdr, sizeof(hdr));
    memcpy(blob + sizeof(hdr), key->u.rsa.e, key->u.rsa.e_len);
    memcpy(blob + sizeof(hdr) + key->u.rsa.e_len,
           key->u.rsa.n, key->u.rsa.n_len);

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return HLM_E_UNSUPPORTED_ALG;
    st = BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hkey,
                             blob, (ULONG)blob_len, 0);
    if (!NT_SUCCESS(st)) goto done;

    st = cng_sha256(msg, msg_len, hash);
    if (!NT_SUCCESS(st)) goto done;
    hash_len = HLM_SHA256_DIGEST_SIZE;

    pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    st = BCryptVerifySignature(hkey, &pad, hash, hash_len,
                               (PUCHAR)sig, (ULONG)sig_len, BCRYPT_PAD_PKCS1);
    result = NT_SUCCESS(st) ? 1 : 0;

done:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

static int cng_verify_ecdsa(const hlm_public_key *key,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS st;
    int result = 0;
    UCHAR hash[HLM_SHA256_DIGEST_SIZE];
    UCHAR blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB hdr;

    if (sig_len != 64) return 0;

    hdr.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr.cbKey = 32;
    memcpy(blob, &hdr, sizeof(hdr));
    memcpy(blob + sizeof(hdr), key->u.ec.x, 32);
    memcpy(blob + sizeof(hdr) + 32, key->u.ec.y, 32);

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return HLM_E_UNSUPPORTED_ALG;
    st = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hkey,
                             blob, sizeof(blob), 0);
    if (!NT_SUCCESS(st)) goto done;

    st = cng_sha256(msg, msg_len, hash);
    if (!NT_SUCCESS(st)) goto done;

    /* CNG takes the raw r||s layout — exactly the JWS ES256 signature. */
    st = BCryptVerifySignature(hkey, NULL, hash, HLM_SHA256_DIGEST_SIZE,
                               (PUCHAR)sig, (ULONG)sig_len, 0);
    result = NT_SUCCESS(st) ? 1 : 0;

done:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

static int cng_verify(void *user, const hlm_public_key *key,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len)
{
    (void)user;
#if SIZE_MAX > ULONG_MAX
    /* every CNG length parameter is a ULONG; refuse instead of truncating */
    if (msg_len > ULONG_MAX || sig_len > ULONG_MAX) return 0;
#endif
    switch (key->alg) {
    case HLM_ALG_RS256:
        return cng_verify_rsa(key, msg, msg_len, sig, sig_len);
    case HLM_ALG_ES256:
        return cng_verify_ecdsa(key, msg, msg_len, sig, sig_len);
    case HLM_ALG_EDDSA:
        if (sig_len != 64) return 0;
        return hlm_ed25519_verify(key->u.ed25519.pub, msg, msg_len, sig);
    default:
        return HLM_E_UNSUPPORTED_ALG;
    }
}

hlm_crypto hlm_crypto_cng(void)
{
    hlm_crypto c;
    c.verify = cng_verify;
    c.user = 0;
    return c;
}

#endif /* _WIN32 */
