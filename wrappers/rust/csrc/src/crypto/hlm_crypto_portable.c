/* Built-in dependency-free crypto backend: RS256 + ES256 + EdDSA. */
#include "hymma/hlm.h"
#include "hlm_rsa.h"
#include "hlm_p256.h"
#include "hlm_ed25519.h"

static int portable_verify(void *user, const hlm_public_key *key,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    (void)user;

    switch (key->alg) {
    case HLM_ALG_RS256:
        return hlm_rsa_pkcs1_sha256_verify(key->u.rsa.n, key->u.rsa.n_len,
                                           key->u.rsa.e, key->u.rsa.e_len,
                                           msg, msg_len, sig, sig_len);
    case HLM_ALG_ES256:
        if (sig_len != 64) return 0;
        return hlm_p256_ecdsa_sha256_verify(key->u.ec.x, key->u.ec.y,
                                            msg, msg_len, sig);
    case HLM_ALG_EDDSA:
        if (sig_len != 64) return 0;
        return hlm_ed25519_verify(key->u.ed25519.pub, msg, msg_len, sig);
    default:
        return HLM_E_UNSUPPORTED_ALG;
    }
}

hlm_crypto hlm_crypto_portable(void)
{
    hlm_crypto c;
    c.verify = portable_verify;
    c.user = 0;
    return c;
}
