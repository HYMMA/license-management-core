/* Windows CNG (bcrypt) crypto backend — RS256 + ES256 via the OS.
 * EdDSA delegates to the portable Ed25519 verifier: CNG has no Ed25519
 * support, and apps that pick this backend should still verify every
 * format the server signs. */
#if defined(_WIN32)

#include <windows.h>
#include <bcrypt.h>
#include <string.h>

#include "hymma/hlm.h"
#include "hlm_ed25519.h"

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

static int cng_verify_rsa(const hlm_public_key *key,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS st;
    int result = 0;
    UCHAR hash[32];
    DWORD hash_len = 0, cb = 0;
    BCRYPT_PKCS1_PADDING_INFO pad;
    UCHAR blob[8192];
    BCRYPT_RSAKEY_BLOB *hdr = (BCRYPT_RSAKEY_BLOB *)blob;
    size_t blob_len;

    /* Build a BCRYPT_RSAPUBLIC_BLOB: header | exponent | modulus */
    blob_len = sizeof(BCRYPT_RSAKEY_BLOB) + key->u.rsa.e_len + key->u.rsa.n_len;
    if (blob_len > sizeof(blob)) return HLM_E_ARG;
    hdr->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    hdr->BitLength = (ULONG)(key->u.rsa.n_len * 8);
    hdr->cbPublicExp = (ULONG)key->u.rsa.e_len;
    hdr->cbModulus = (ULONG)key->u.rsa.n_len;
    hdr->cbPrime1 = 0;
    hdr->cbPrime2 = 0;
    memcpy(blob + sizeof(BCRYPT_RSAKEY_BLOB), key->u.rsa.e, key->u.rsa.e_len);
    memcpy(blob + sizeof(BCRYPT_RSAKEY_BLOB) + key->u.rsa.e_len,
           key->u.rsa.n, key->u.rsa.n_len);

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return HLM_E_UNSUPPORTED_ALG;
    st = BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hkey,
                             blob, (ULONG)blob_len, 0);
    if (!NT_SUCCESS(st)) goto done;

    /* SHA-256 of msg via CNG too (keeps this backend self-contained). */
    {
        BCRYPT_ALG_HANDLE halg = NULL;
        st = BCryptOpenAlgorithmProvider(&halg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(st)) goto done;
        st = BCryptHash(halg, NULL, 0, (PUCHAR)msg, (ULONG)msg_len, hash, 32);
        BCryptCloseAlgorithmProvider(halg, 0);
        if (!NT_SUCCESS(st)) goto done;
        hash_len = 32;
    }

    pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    st = BCryptVerifySignature(hkey, &pad, hash, hash_len,
                               (PUCHAR)sig, (ULONG)sig_len, BCRYPT_PAD_PKCS1);
    result = NT_SUCCESS(st) ? 1 : 0;

done:
    (void)cb;
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
    UCHAR hash[32];
    UCHAR blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;

    if (sig_len != 64) return 0;

    hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr->cbKey = 32;
    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), key->u.ec.x, 32);
    memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB) + 32, key->u.ec.y, 32);

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return HLM_E_UNSUPPORTED_ALG;
    st = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hkey,
                             blob, sizeof(blob), 0);
    if (!NT_SUCCESS(st)) goto done;

    {
        BCRYPT_ALG_HANDLE halg = NULL;
        st = BCryptOpenAlgorithmProvider(&halg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(st)) goto done;
        st = BCryptHash(halg, NULL, 0, (PUCHAR)msg, (ULONG)msg_len, hash, 32);
        BCryptCloseAlgorithmProvider(halg, 0);
        if (!NT_SUCCESS(st)) goto done;
    }

    /* CNG takes the raw r||s layout — exactly the JWS ES256 signature. */
    st = BCryptVerifySignature(hkey, NULL, hash, 32,
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
