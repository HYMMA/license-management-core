/* Compact JWS (RFC 7515) verification and JWK (RFC 7517) parsing. */
#include <string.h>

#include "hymma/hlm.h"
#include "hlm_b64url.h"
#include "hlm_json.h"

const char *hlm_err_str(int err)
{
    switch (err) {
    case HLM_OK: return "ok";
    case HLM_E_ARG: return "invalid argument";
    case HLM_E_BUFFER: return "buffer too small";
    case HLM_E_FORMAT: return "malformed input";
    case HLM_E_SIGNATURE: return "signature verification failed";
    case HLM_E_UNSUPPORTED_ALG: return "unsupported algorithm";
    case HLM_E_NO_LICENSE: return "no license available";
    case HLM_E_HTTP: return "network transport failure";
    case HLM_E_API: return "server rejected the request";
    case HLM_E_STORAGE: return "license storage failure";
    case HLM_E_PRODUCT_MISMATCH: return "license is for a different product";
    case HLM_E_COMPUTER_MISMATCH: return "license is for a different computer";
    case HLM_E_AUTH: return "invalid API key";
    default: return "unknown error";
    }
}

static int alg_from_name(const char *name, size_t len, hlm_alg *out)
{
    if (len == 5 && memcmp(name, "RS256", 5) == 0) { *out = HLM_ALG_RS256; return 0; }
    if (len == 5 && memcmp(name, "ES256", 5) == 0) { *out = HLM_ALG_ES256; return 0; }
    if (len == 5 && memcmp(name, "EdDSA", 5) == 0) { *out = HLM_ALG_EDDSA; return 0; }
    return -1;
}

int hlm_jws_verify(const char *jws, size_t jws_len,
                   const hlm_public_key *keys, size_t key_count,
                   const hlm_crypto *crypto,
                   uint8_t *workbuf, size_t workbuf_len,
                   const char **payload_out, size_t *payload_len_out)
{
    const char *dot1, *dot2;
    size_t h_len, p_len, s_len;
    char header_json[256];
    uint8_t sig[512 + 8];
    size_t header_len, sig_len, payload_len;
    hlm_json_tok toks[16];
    hlm_json_doc doc;
    hlm_alg alg;
    int ntok, alg_tok, any_alg_key = 0;
    size_t i;
    int verified = 0;

    if (jws == NULL || keys == NULL || key_count == 0 || crypto == NULL ||
        crypto->verify == NULL || workbuf == NULL || payload_out == NULL)
        return HLM_E_ARG;

    /* Trim surrounding whitespace (files often end with a newline). */
    while (jws_len > 0 && (jws[0] == ' ' || jws[0] == '\r' || jws[0] == '\n' ||
                           jws[0] == '\t')) { jws++; jws_len--; }
    while (jws_len > 0 && (jws[jws_len - 1] == ' ' || jws[jws_len - 1] == '\r' ||
                           jws[jws_len - 1] == '\n' || jws[jws_len - 1] == '\t'))
        jws_len--;

    dot1 = (const char *)memchr(jws, '.', jws_len);
    if (dot1 == NULL) return HLM_E_FORMAT;
    dot2 = (const char *)memchr(dot1 + 1, '.', (size_t)(jws + jws_len - dot1 - 1));
    if (dot2 == NULL) return HLM_E_FORMAT;
    if (memchr(dot2 + 1, '.', (size_t)(jws + jws_len - dot2 - 1)) != NULL)
        return HLM_E_FORMAT; /* JWE or garbage */

    h_len = (size_t)(dot1 - jws);
    p_len = (size_t)(dot2 - dot1 - 1);
    s_len = (size_t)(jws + jws_len - dot2 - 1);
    if (h_len == 0 || p_len == 0 || s_len == 0) return HLM_E_FORMAT;

    /* Header */
    header_len = hlm_b64url_decode(jws, h_len, (uint8_t *)header_json,
                                   sizeof(header_json) - 1);
    if (header_len == (size_t)-1) return HLM_E_FORMAT;
    header_json[header_len] = '\0';

    ntok = hlm_json_parse(header_json, header_len, toks,
                          (int)(sizeof(toks) / sizeof(toks[0])));
    if (ntok <= 0) return HLM_E_FORMAT;
    hlm_json_doc_init(&doc, header_json, header_len, toks, ntok);
    alg_tok = hlm_json_member(&doc, 0, "alg");
    if (alg_tok < 0) return HLM_E_FORMAT;
    {
        size_t alen;
        const char *aname = hlm_json_raw(&doc, alg_tok, &alen);
        if (aname == NULL || alg_from_name(aname, alen, &alg) < 0)
            return HLM_E_UNSUPPORTED_ALG;
    }

    /* Signature */
    sig_len = hlm_b64url_decode(dot2 + 1, s_len, sig, sizeof(sig));
    if (sig_len == (size_t)-1) return HLM_E_FORMAT;

    /* The signing input is the raw ASCII "header.payload" — verify without
     * re-encoding anything. */
    for (i = 0; i < key_count; i++) {
        int r;
        if (keys[i].alg != alg) continue;
        any_alg_key = 1;
        r = crypto->verify(crypto->user, &keys[i],
                           (const uint8_t *)jws, (size_t)(dot2 - jws),
                           sig, sig_len);
        if (r == 1) { verified = 1; break; }
        if (r == HLM_E_UNSUPPORTED_ALG) return HLM_E_UNSUPPORTED_ALG;
    }

    if (!any_alg_key) return HLM_E_UNSUPPORTED_ALG;
    if (!verified) return HLM_E_SIGNATURE;

    /* Payload */
    payload_len = hlm_b64url_decode(dot1 + 1, p_len, workbuf, workbuf_len);
    if (payload_len == (size_t)-1) return HLM_E_BUFFER;

    *payload_out = (const char *)workbuf;
    if (payload_len_out) *payload_len_out = payload_len;
    return HLM_OK;
}

/* ------------------------------------------------------------------ */
/* JWK                                                                 */
/* ------------------------------------------------------------------ */

static int jwk_decode_member(const hlm_json_doc *doc, int obj, const char *name,
                             uint8_t **cursor, uint8_t *end,
                             const uint8_t **out, size_t *out_len)
{
    char tmp[1024];
    size_t raw_len, dec;
    int tok = hlm_json_member(doc, obj, name);

    if (tok < 0) return -1;
    raw_len = hlm_json_string(doc, tok, tmp, sizeof(tmp));
    if (raw_len == (size_t)-1) return -1;
    dec = hlm_b64url_decode(tmp, raw_len, *cursor, (size_t)(end - *cursor));
    if (dec == (size_t)-1) return -1;
    *out = *cursor;
    *out_len = dec;
    *cursor += dec;
    return 0;
}

int hlm_jwk_parse(const char *jwk_json, size_t len,
                  hlm_public_key *key, uint8_t *keybuf, size_t keybuf_len)
{
    hlm_json_tok toks[32];
    hlm_json_doc doc;
    int ntok, kty_tok;
    char kty[16];
    uint8_t *cursor = keybuf;
    uint8_t *end = keybuf + keybuf_len;

    if (jwk_json == NULL || key == NULL || keybuf == NULL) return HLM_E_ARG;

    ntok = hlm_json_parse(jwk_json, len, toks,
                          (int)(sizeof(toks) / sizeof(toks[0])));
    if (ntok <= 0) return HLM_E_FORMAT;
    hlm_json_doc_init(&doc, jwk_json, len, toks, ntok);

    kty_tok = hlm_json_member(&doc, 0, "kty");
    if (kty_tok < 0 ||
        hlm_json_string(&doc, kty_tok, kty, sizeof(kty)) == (size_t)-1)
        return HLM_E_FORMAT;

    if (strcmp(kty, "RSA") == 0) {
        key->alg = HLM_ALG_RS256;
        if (jwk_decode_member(&doc, 0, "n", &cursor, end,
                              &key->u.rsa.n, &key->u.rsa.n_len) < 0 ||
            jwk_decode_member(&doc, 0, "e", &cursor, end,
                              &key->u.rsa.e, &key->u.rsa.e_len) < 0)
            return HLM_E_FORMAT;
        return HLM_OK;
    }

    if (strcmp(kty, "EC") == 0) {
        const uint8_t *x, *y;
        size_t xl, yl;
        key->alg = HLM_ALG_ES256;
        if (jwk_decode_member(&doc, 0, "x", &cursor, end, &x, &xl) < 0 ||
            jwk_decode_member(&doc, 0, "y", &cursor, end, &y, &yl) < 0 ||
            xl != 32 || yl != 32)
            return HLM_E_FORMAT;
        key->u.ec.x = x;
        key->u.ec.y = y;
        return HLM_OK;
    }

    if (strcmp(kty, "OKP") == 0) {
        const uint8_t *x;
        size_t xl;
        key->alg = HLM_ALG_EDDSA;
        if (jwk_decode_member(&doc, 0, "x", &cursor, end, &x, &xl) < 0 ||
            xl != 32)
            return HLM_E_FORMAT;
        key->u.ed25519.pub = x;
        return HLM_OK;
    }

    return HLM_E_UNSUPPORTED_ALG;
}
