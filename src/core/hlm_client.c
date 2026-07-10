/* High-level client: the .NET SDK's Install/Launch/Activate flows over the
 * documented REST endpoints, always requesting a portable JWS license.
 *
 * Wire contract (matches LicenseManagement.EndUser):
 *   POST  computer                {"MacAddress","Name"}          201|409 = ok
 *   GET   computer?macAddress=    -> {"id":"PC_...", ...}
 *   POST  license                 {"Product","Computer"}         201|409 = ok
 *   GET   license?computer=&product=&validDays=&format=jws|es256|eddsa
 *   PATCH license                 {"License","Code"}             204 = ok,
 *                                 Code:null frees the seat, 404 -> re-POST
 * Headers: X-API-KEY (PUB_ client key), X-Correlation-Id,
 *          Idempotency-Key on POSTs ("computer:{mac}:{name}" / "license:{pc}:{prd}").
 */
#include <stdio.h>
#include <string.h>

#include "hymma/hlm.h"
#include "hlm_json.h"

#define HLM_DEFAULT_BASE_URL "https://license-management.com/api/"
#define HLM_DEFAULT_VALID_DAYS 90u

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static size_t json_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (; *in != '\0'; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            if (o + 2 >= cap) return (size_t)-1;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            if (o + 6 >= cap) return (size_t)-1;
            o += (size_t)snprintf(out + o, cap - o, "\\u%04x", c);
        } else {
            if (o + 1 >= cap) return (size_t)-1;
            out[o++] = (char)c;
        }
    }
    if (o >= cap) return (size_t)-1;
    out[o] = '\0';
    return o;
}

static void make_correlation_id(hlm_client *c, char out[33])
{
    static const char HEX[] = "0123456789abcdef";
    static uint32_t counter;
    uint64_t seed;
    int i;

    counter += 0x9e3779b9u;
    seed = (uint64_t)(c->cfg.clock.now ? c->cfg.clock.now(c->cfg.clock.user) : 0);
    seed = seed * 6364136223846793005ULL + counter;

    for (i = 0; i < 32; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = HEX[(seed >> 60) & 0xf];
    }
    out[32] = '\0';
}

static const char *format_param(hlm_alg alg)
{
    switch (alg) {
    case HLM_ALG_ES256: return "es256";
    case HLM_ALG_EDDSA: return "eddsa";
    default: return "jws";
    }
}

/* Send one request; body lands in c->resp (NUL-terminated).
 * Returns HLM_OK when a response was received, HLM_E_HTTP otherwise. */
static int send_req(hlm_client *c, const char *method, const char *path_query,
                    const char *body, const char *idempotency_key,
                    int *status_out)
{
    hlm_http_request req;
    hlm_http_response resp;
    char url[512];
    char corr[33];
    int r;

    if (c->cfg.http.send == NULL) return HLM_E_HTTP;

    if (snprintf(url, sizeof(url), "%s%s", c->cfg.base_url, path_query) >=
        (int)sizeof(url))
        return HLM_E_ARG;

    make_correlation_id(c, corr);

    req.method = method;
    req.url = url;
    req.body = body;
    req.api_key = c->cfg.client_api_key;
    req.idempotency_key = idempotency_key;
    req.correlation_id = corr;

    resp.status = 0;
    resp.body = c->resp;
    resp.body_cap = sizeof(c->resp) - 1;
    resp.body_len = 0;

    r = c->cfg.http.send(c->cfg.http.user, &req, &resp);
    if (r != HLM_OK || resp.status == 0) return HLM_E_HTTP;

    c->resp[resp.body_len < sizeof(c->resp) ? resp.body_len
                                            : sizeof(c->resp) - 1] = '\0';
    c->last_http_status = resp.status;
    *status_out = resp.status;
    return HLM_OK;
}

static int map_api_error(int status)
{
    if (status == 401 || status == 403) return HLM_E_AUTH;
    return HLM_E_API;
}

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

int hlm_client_init(hlm_client *c, const hlm_client_cfg *cfg)
{
    if (c == NULL || cfg == NULL) return HLM_E_ARG;
    if (cfg->product_id == NULL || cfg->keys == NULL || cfg->key_count == 0 ||
        cfg->crypto.verify == NULL || cfg->machine_id == NULL ||
        cfg->machine_name == NULL)
        return HLM_E_ARG;

    memset(c, 0, sizeof(*c));
    c->cfg = *cfg;
    if (c->cfg.base_url == NULL) c->cfg.base_url = HLM_DEFAULT_BASE_URL;
    if (c->cfg.valid_days == 0) c->cfg.valid_days = HLM_DEFAULT_VALID_DAYS;
    if (c->cfg.format == 0) c->cfg.format = HLM_ALG_RS256;
    if (c->cfg.clock.now == NULL) c->cfg.clock = hlm_clock_system();
    return HLM_OK;
}

/* ------------------------------------------------------------------ */
/* verify + adopt a signed license string                              */
/* ------------------------------------------------------------------ */

static int adopt_license(hlm_client *c, const char *jws, size_t len)
{
    hlm_license lic;
    hlm_status status;
    int64_t now = c->cfg.clock.now(c->cfg.clock.user);
    int r = hlm_license_check(jws, len, c->cfg.keys, c->cfg.key_count,
                              &c->cfg.crypto, c->cfg.product_id,
                              c->cfg.machine_id, now, &lic, &status);
    if (r != HLM_OK) return r;

    c->license = lic;
    c->status = status;
    c->has_license = 1;
    return HLM_OK;
}

/* ------------------------------------------------------------------ */
/* server flow                                                         */
/* ------------------------------------------------------------------ */

/* POST computer + GET computer -> computer id in `pc_id`. */
static int ensure_computer(hlm_client *c, char *pc_id, size_t pc_id_cap)
{
    char mac_esc[HLM_MAX_MACHINE_ID * 2], name_esc[HLM_MAX_NAME * 2];
    char body[512], idem[256], path[512];
    int status, r;

    if (json_escape(c->cfg.machine_id, mac_esc, sizeof(mac_esc)) == (size_t)-1 ||
        json_escape(c->cfg.machine_name, name_esc, sizeof(name_esc)) == (size_t)-1)
        return HLM_E_ARG;

    snprintf(body, sizeof(body), "{\"MacAddress\":\"%s\",\"Name\":\"%s\"}",
             mac_esc, name_esc);
    snprintf(idem, sizeof(idem), "computer:%s:%s", c->cfg.machine_id,
             c->cfg.machine_name);

    r = send_req(c, "POST", "computer", body, idem, &status);
    if (r != HLM_OK) return r;
    if (!((status >= 200 && status < 300) || status == 409))
        return map_api_error(status);

    snprintf(path, sizeof(path), "computer?macAddress=%s", c->cfg.machine_id);
    r = send_req(c, "GET", path, NULL, NULL, &status);
    if (r != HLM_OK) return r;
    if (status < 200 || status >= 300) return map_api_error(status);

    {
        hlm_json_tok toks[64];
        hlm_json_doc doc;
        int ntok = hlm_json_parse(c->resp, strlen(c->resp), toks, 64);
        int t;
        if (ntok <= 0) return HLM_E_FORMAT;
        hlm_json_doc_init(&doc, c->resp, strlen(c->resp), toks, ntok);
        t = hlm_json_member(&doc, 0, "id");
        if (t < 0) t = hlm_json_member(&doc, 0, "Id");
        if (t < 0 ||
            hlm_json_string(&doc, t, pc_id, pc_id_cap) == (size_t)-1)
            return HLM_E_FORMAT;
    }
    return HLM_OK;
}

static int post_license(hlm_client *c, const char *pc_id)
{
    char body[256], idem[256];
    int status, r;

    snprintf(body, sizeof(body), "{\"Product\":\"%s\",\"Computer\":\"%s\"}",
             c->cfg.product_id, pc_id);
    snprintf(idem, sizeof(idem), "license:%s:%s", pc_id, c->cfg.product_id);

    r = send_req(c, "POST", "license", body, idem, &status);
    if (r != HLM_OK) return r;
    if (!((status >= 200 && status < 300) || status == 409))
        return map_api_error(status);
    return HLM_OK;
}

static int get_signed_license(hlm_client *c, const char *pc_id)
{
    char path[512];
    int status, r;
    size_t len;

    snprintf(path, sizeof(path),
             "license?computer=%s&product=%s&validDays=%u&format=%s",
             pc_id, c->cfg.product_id, c->cfg.valid_days,
             format_param(c->cfg.format));

    r = send_req(c, "GET", path, NULL, NULL, &status);
    if (r != HLM_OK) return r;
    if (status < 200 || status >= 300) return map_api_error(status);

    len = strlen(c->resp);
    if (len == 0 || c->resp[0] == '<') return HLM_E_FORMAT; /* XML => bad format param */

    r = adopt_license(c, c->resp, len);
    if (r != HLM_OK) return r;

    /* Cache the raw signed string verbatim (like the SDK caches the XML). */
    if (c->cfg.storage.write != NULL) {
        if (c->cfg.storage.write(c->cfg.storage.user, c->resp, len) != HLM_OK)
            return HLM_E_STORAGE;
    }
    return HLM_OK;
}

int hlm_client_refresh(hlm_client *c)
{
    char pc_id[HLM_MAX_ID];
    int r;

    if (c == NULL) return HLM_E_ARG;

    r = ensure_computer(c, pc_id, sizeof(pc_id));
    if (r != HLM_OK) return r;
    r = post_license(c, pc_id);
    if (r != HLM_OK) return r;
    return get_signed_license(c, pc_id);
}

int hlm_client_check(hlm_client *c)
{
    int r;

    if (c == NULL) return HLM_E_ARG;

    if (c->cfg.storage.read != NULL) {
        int n = c->cfg.storage.read(c->cfg.storage.user, c->buf,
                                    sizeof(c->buf) - 1);
        if (n > 0) {
            c->buf[n] = '\0';
            r = adopt_license(c, c->buf, (size_t)n);
            if (r == HLM_OK && c->status != HLM_STATUS_EXPIRED)
                return HLM_OK;
            /* tampered, mismatched or lapsed cache: fall through to refresh */
        }
    }

    r = hlm_client_refresh(c);
    if (r == HLM_E_HTTP && c->has_license) {
        /* offline but we hold a verified (if expired) license — surface it */
        return HLM_OK;
    }
    if (r == HLM_E_HTTP && c->cfg.http.send == NULL) return HLM_E_NO_LICENSE;
    return r;
}

static int patch_license(hlm_client *c, const char *code_or_null)
{
    char body[512];
    int status, r;

    if (!c->has_license) return HLM_E_NO_LICENSE;

    if (code_or_null != NULL) {
        char code_esc[HLM_MAX_CODE * 2];
        if (json_escape(code_or_null, code_esc, sizeof(code_esc)) == (size_t)-1)
            return HLM_E_ARG;
        snprintf(body, sizeof(body), "{\"License\":\"%s\",\"Code\":\"%s\"}",
                 c->license.id, code_esc);
    } else {
        snprintf(body, sizeof(body), "{\"License\":\"%s\",\"Code\":null}",
                 c->license.id);
    }

    r = send_req(c, "PATCH", "license", body, NULL, &status);
    if (r != HLM_OK) return r;

    if (status == 404) {
        /* license row rotated server-side: recreate, then retry the patch */
        r = hlm_client_refresh(c);
        if (r != HLM_OK) return r;
        r = send_req(c, "PATCH", "license", body, NULL, &status);
        if (r != HLM_OK) return r;
    }

    if (status != 204 && (status < 200 || status >= 300))
        return map_api_error(status);
    return HLM_OK;
}

int hlm_client_activate(hlm_client *c, const char *receipt_code)
{
    int r;

    if (c == NULL || receipt_code == NULL || receipt_code[0] == '\0')
        return HLM_E_ARG;

    if (!c->has_license) {
        r = hlm_client_check(c);
        if (r != HLM_OK) return r;
    }

    r = patch_license(c, receipt_code);
    if (r != HLM_OK) return r;
    return hlm_client_refresh(c);
}

int hlm_client_deactivate(hlm_client *c)
{
    int r;

    if (c == NULL) return HLM_E_ARG;

    if (!c->has_license) {
        r = hlm_client_check(c);
        if (r != HLM_OK) return r;
    }

    r = patch_license(c, NULL);
    if (r != HLM_OK) return r;
    return hlm_client_refresh(c);
}
