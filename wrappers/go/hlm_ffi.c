/* Flat FFI implementation over the core client + built-in ports. */
#include <stdlib.h>
#include <string.h>

#include "hymma/hlm.h"
#include "hymma/hlm_ffi.h"
#include "hlm_json.h"

#define FFI_MAX_KEYS 4
#define FFI_KEYBUF 2048
#define FFI_MAX_STR 512

struct hlm_ffi_client {
    hlm_client client;
    hlm_public_key keys[FFI_MAX_KEYS];
    uint8_t keybuf[FFI_KEYBUF];
    char product_id[FFI_MAX_STR];
    char api_key[FFI_MAX_STR];
    char base_url[FFI_MAX_STR];
    char machine_id[HLM_MAX_MACHINE_ID];
    char machine_name[HLM_MAX_NAME];
    char license_path[FFI_MAX_STR];
    hlm_storage_file_cfg storage_cfg;
};

/* Parse a JWK object or array of JWK objects. */
static int parse_jwks(const char *jwks_json, hlm_public_key *keys,
                      size_t max_keys, uint8_t *keybuf, size_t keybuf_len,
                      size_t *count_out)
{
    hlm_json_tok toks[128];
    hlm_json_doc doc;
    size_t len = strlen(jwks_json);
    int ntok = hlm_json_parse(jwks_json, len, toks, 128);
    size_t count = 0;
    uint8_t *cursor = keybuf;

    if (ntok <= 0) return HLM_E_FORMAT;
    hlm_json_doc_init(&doc, jwks_json, len, toks, ntok);

    if (doc.toks[0].type == HLM_JSON_OBJECT) {
        int r = hlm_jwk_parse(jwks_json, len, &keys[0], keybuf, keybuf_len);
        if (r != HLM_OK) return r;
        *count_out = 1;
        return HLM_OK;
    }

    if (doc.toks[0].type != HLM_JSON_ARRAY) return HLM_E_FORMAT;

    for (count = 0; count < max_keys; count++) {
        int el = hlm_json_element(&doc, 0, (int)count);
        const char *span;
        size_t span_len;
        int r;

        if (el < 0) break;
        span = doc.src + doc.toks[el].start;
        span_len = (size_t)(doc.toks[el].end - doc.toks[el].start);
        r = hlm_jwk_parse(span, span_len, &keys[count], cursor,
                          (size_t)(keybuf + keybuf_len - cursor));
        if (r != HLM_OK) return r;
        /* advance cursor past what this key consumed: worst-case RSA-4096 */
        cursor += 528;
        if (cursor >= keybuf + keybuf_len) break;
    }

    if (count == 0) return HLM_E_FORMAT;
    *count_out = count;
    return HLM_OK;
}

static int copy_str(char *dst, size_t cap, const char *src)
{
    size_t n;
    if (src == NULL) { dst[0] = '\0'; return 0; }
    n = strlen(src);
    if (n >= cap) return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

HLM_API hlm_ffi_client *hlm_ffi_create(const char *base_url,
                                       const char *product_id,
                                       const char *client_api_key,
                                       const char *jwks_json,
                                       int format,
                                       unsigned valid_days,
                                       const char *machine_id,
                                       const char *machine_name,
                                       const char *license_path)
{
    hlm_ffi_client *c;
    hlm_client_cfg cfg;
    size_t key_count = 0;

    if (product_id == NULL || client_api_key == NULL || jwks_json == NULL)
        return NULL;

    c = (hlm_ffi_client *)calloc(1, sizeof(*c));
    if (c == NULL) return NULL;

    if (copy_str(c->product_id, sizeof(c->product_id), product_id) < 0 ||
        copy_str(c->api_key, sizeof(c->api_key), client_api_key) < 0 ||
        copy_str(c->base_url, sizeof(c->base_url), base_url) < 0 ||
        copy_str(c->license_path, sizeof(c->license_path), license_path) < 0)
        goto fail;

    if (parse_jwks(jwks_json, c->keys, FFI_MAX_KEYS, c->keybuf,
                   sizeof(c->keybuf), &key_count) != HLM_OK)
        goto fail;

    if (machine_id != NULL) {
        if (copy_str(c->machine_id, sizeof(c->machine_id), machine_id) < 0)
            goto fail;
    } else {
#if defined(_WIN32)
        if (hlm_machine_id_win(c->machine_id, sizeof(c->machine_id)) != HLM_OK)
            goto fail;
#else
        if (hlm_machine_id_posix(c->machine_id, sizeof(c->machine_id)) != HLM_OK)
            goto fail;
#endif
    }

    if (machine_name != NULL) {
        if (copy_str(c->machine_name, sizeof(c->machine_name), machine_name) < 0)
            goto fail;
    } else {
#if defined(_WIN32)
        if (hlm_machine_name_win(c->machine_name, sizeof(c->machine_name)) != HLM_OK)
            goto fail;
#else
        if (hlm_machine_name_posix(c->machine_name, sizeof(c->machine_name)) != HLM_OK)
            goto fail;
#endif
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.base_url = c->base_url[0] != '\0' ? c->base_url : NULL;
    cfg.product_id = c->product_id;
    cfg.client_api_key = c->api_key;
    cfg.valid_days = valid_days;
    cfg.format = format >= HLM_ALG_RS256 && format <= HLM_ALG_EDDSA
                     ? (hlm_alg)format
                     : HLM_ALG_RS256;
    cfg.keys = c->keys;
    cfg.key_count = key_count;
    cfg.machine_id = c->machine_id;
    cfg.machine_name = c->machine_name;
    cfg.crypto = hlm_crypto_portable();
    cfg.clock = hlm_clock_system();
#if defined(_WIN32)
    cfg.http = hlm_http_winhttp();
    cfg.sleep = hlm_sleep_win();
    cfg.timesync = hlm_timesync_win(); /* clock-tamper cascade, like the SDK */
#else
    cfg.http = hlm_http_curl();
    cfg.sleep = hlm_sleep_posix();
    cfg.timesync = hlm_timesync_posix();
#endif
    if (c->license_path[0] != '\0') {
        c->storage_cfg.path = c->license_path;
        cfg.storage = hlm_storage_file(&c->storage_cfg);
    }

    if (hlm_client_init(&c->client, &cfg) != HLM_OK) goto fail;

    /* hlm_client_init copied cfg by value; re-point the port user data at
     * the storage cfg that lives inside THIS handle. */
    if (c->license_path[0] != '\0')
        c->client.cfg.storage.user = &c->storage_cfg;

    return c;

fail:
    free(c);
    return NULL;
}

HLM_API void hlm_ffi_destroy(hlm_ffi_client *c)
{
    free(c);
}

HLM_API int hlm_ffi_check(hlm_ffi_client *c)
{
    if (c == NULL) return HLM_E_ARG;
    return hlm_client_check(&c->client);
}

HLM_API int hlm_ffi_activate(hlm_ffi_client *c, const char *receipt_code)
{
    if (c == NULL) return HLM_E_ARG;
    return hlm_client_activate(&c->client, receipt_code);
}

HLM_API int hlm_ffi_deactivate(hlm_ffi_client *c)
{
    if (c == NULL) return HLM_E_ARG;
    return hlm_client_deactivate(&c->client);
}

HLM_API int hlm_ffi_refresh(hlm_ffi_client *c)
{
    if (c == NULL) return HLM_E_ARG;
    return hlm_client_refresh(&c->client);
}

HLM_API int hlm_ffi_status(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license) return HLM_STATUS_UNKNOWN;
    return (int)c->client.status;
}

HLM_API const char *hlm_ffi_status_name(hlm_ffi_client *c)
{
    return hlm_status_str((hlm_status)hlm_ffi_status(c));
}

HLM_API const char *hlm_ffi_license_id(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license) return "";
    return c->client.license.id;
}

HLM_API const char *hlm_ffi_product_name(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license) return "";
    return c->client.license.product.name;
}

HLM_API const char *hlm_ffi_buyer_email(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license || !c->client.license.has_receipt)
        return "";
    return c->client.license.receipt.buyer_email;
}

HLM_API int64_t hlm_ffi_expires(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license) return HLM_TIME_NONE;
    return c->client.license.expires;
}

HLM_API int64_t hlm_ffi_trial_end(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license) return HLM_TIME_NONE;
    return c->client.license.trial_end;
}

HLM_API int64_t hlm_ffi_receipt_expires(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license || !c->client.license.has_receipt)
        return HLM_TIME_NONE;
    return c->client.license.receipt.expires;
}

HLM_API int hlm_ffi_live_mode(hlm_ffi_client *c)
{
    if (c == NULL || !c->client.has_license) return 1;
    return c->client.license.live_mode;
}

HLM_API const char *hlm_ffi_metadata(hlm_ffi_client *c, const char *key)
{
    int i;
    if (c == NULL || !c->client.has_license || key == NULL) return "";
    for (i = 0; i < c->client.license.metadata_count; i++) {
        if (strcmp(c->client.license.metadata[i].key, key) == 0)
            return c->client.license.metadata[i].value;
    }
    return "";
}

HLM_API int hlm_ffi_last_http_status(hlm_ffi_client *c)
{
    return c == NULL ? 0 : c->client.last_http_status;
}

HLM_API const char *hlm_ffi_last_error_detail(hlm_ffi_client *c)
{
    return c == NULL ? "" : c->client.last_error;
}

HLM_API const char *hlm_ffi_err_name(int err)
{
    return hlm_err_str(err);
}

HLM_API int hlm_ffi_machine_id(char *out, int cap)
{
#if defined(_WIN32)
    return hlm_machine_id_win(out, (size_t)cap);
#else
    return hlm_machine_id_posix(out, (size_t)cap);
#endif
}

HLM_API int hlm_ffi_machine_name(char *out, int cap)
{
#if defined(_WIN32)
    return hlm_machine_name_win(out, (size_t)cap);
#else
    return hlm_machine_name_posix(out, (size_t)cap);
#endif
}

HLM_API int hlm_ffi_verify(const char *jws,
                           const char *jwks_json,
                           const char *expected_product_id,
                           const char *expected_machine_id,
                           int64_t now,
                           int *status_out)
{
    hlm_public_key keys[FFI_MAX_KEYS];
    uint8_t keybuf[FFI_KEYBUF];
    size_t key_count = 0;
    hlm_license lic;
    hlm_status status;
    hlm_crypto crypto = hlm_crypto_portable();
    int r;

    if (jws == NULL || jwks_json == NULL || status_out == NULL)
        return HLM_E_ARG;

    r = parse_jwks(jwks_json, keys, FFI_MAX_KEYS, keybuf, sizeof(keybuf),
                   &key_count);
    if (r != HLM_OK) return r;

    if (now == 0) {
        hlm_clock clock = hlm_clock_system();
        now = clock.now(clock.user);
    }

    r = hlm_license_check(jws, strlen(jws), keys, key_count, &crypto,
                          expected_product_id, expected_machine_id, now,
                          &lic, &status);
    if (r != HLM_OK) return r;
    *status_out = (int)status;
    return HLM_OK;
}
