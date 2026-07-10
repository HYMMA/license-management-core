/* Client-flow tests over a scripted mock transport.
 *
 * These mirror the CONCEPTS of the .NET LicenseManagement.EndUser.Test suite:
 *   OnInstall_RegardlessOfLicStatus_ShouldWriteItOnDisk
 *   OnLaunch_ShouldAlways_SetStatus / IfLicExpired_ShouldGetNewOne
 *   OnLaunchFile_IfFileIsModified_ShouldFailToVerify (-> refetch)
 *   OnLaunch_IfProductNameMismatch / IfComputerNameMismatch_ShouldFailToVerify
 *   OnLaunch_AfterCustomerUpdatedProductKey_ShouldGrantAccess
 *   OnUninstall_FromServer_shouldUnregisterComputer / ShouldGetLicOnline /
 *   ShouldUseHardwareMachineId_NotLicFileComputerId / WhenNoLicFileOnDisk /
 *   WrittenLicFile_ShouldBeInUnregisteredState
 *   LicenseEndPoint 201/409 conflict semantics, idempotency keys,
 *   deviceId_Should_includeMachineName
 *   ApiHttp retry policy (429/Retry-After/5xx/501/401)
 *   TimeSyncDiagnostic (clock tamper) + GET DateTime fallback
 *
 * Signed licenses come from tests/vectors/vectors.json (signed by the .NET
 * vectorgen with the server's exact JWS builder), so the mock server serves
 * REAL signatures and the full verify path runs in every flow test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hymma/hlm.h"
#include "hlm_json.h"

static int failures;
static int checks;

#define CHECK(cond, name)                                                    \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            printf("FAIL %s (line %d)\n", name, __LINE__);                   \
        }                                                                    \
    } while (0)

/* ------------------------------------------------------------------ */
/* fixtures from vectors.json                                          */
/* ------------------------------------------------------------------ */

#define BASE_URL "https://api.test/"
#define PRODUCT_ID "PRD_01KWWPEPM0N070BDAHJ7G09RGV"
#define MACHINE_ID "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG"
#define MACHINE_NAME "SHOP-FLOOR-01"
#define PC_ID "PC_01KWVTRYM7AXBT1V56M2N3E3AB"
#define LICENSE_ID "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0"
#define API_KEY "PUB_TESTKEY"

#define T_2026_07_10 1783641600LL /* inside trial */
#define T_2026_08_15 1786752000LL /* after legacy trial end (08-01) */
#define T_2026_11_01 1793491200LL /* after trial file expiry (10-08) */

static char vec_src[131072];
static hlm_json_tok vec_toks[4096];
static hlm_json_doc vec;

static uint8_t rsa_keybuf[1024];
static uint8_t ec_keybuf[128];
static hlm_public_key keys[2];
static size_t key_count;

static char jws_trial[8192];        /* rs256-trial-valid   Expires 2026-10-08 */
static char jws_paid[8192];         /* rs256-paid-valid    Expires 2026-12-01 */
static char jws_unregistered[8192]; /* rs256-receipt-unregistered             */
static char jws_legacy[8192];       /* rs256-legacy-trial  (no Status claim)  */
static char jws_tampered[8192];     /* rs256-tampered-payload                 */

static int load_vectors(const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    int ntok, t;
    const char *raw;
    size_t raw_len;

    if (f == NULL) return -1;
    n = fread(vec_src, 1, sizeof(vec_src) - 1, f);
    fclose(f);
    vec_src[n] = '\0';

    ntok = hlm_json_parse(vec_src, n, vec_toks, 4096);
    if (ntok <= 0) return -1;
    hlm_json_doc_init(&vec, vec_src, n, vec_toks, ntok);

    t = hlm_json_member(&vec, 0, "RsaJwk");
    if (t < 0) return -1;
    raw = vec.src + vec.toks[t].start;
    raw_len = (size_t)(vec.toks[t].end - vec.toks[t].start);
    if (hlm_jwk_parse(raw, raw_len, &keys[0], rsa_keybuf, sizeof(rsa_keybuf)) != HLM_OK)
        return -1;

    t = hlm_json_member(&vec, 0, "EcJwk");
    if (t < 0) return -1;
    raw = vec.src + vec.toks[t].start;
    raw_len = (size_t)(vec.toks[t].end - vec.toks[t].start);
    if (hlm_jwk_parse(raw, raw_len, &keys[1], ec_keybuf, sizeof(ec_keybuf)) != HLM_OK)
        return -1;
    key_count = 2;
    return 0;
}

static int get_case_jws(const char *name, char *out, size_t cap)
{
    int arr = hlm_json_member(&vec, 0, "Cases");
    int i;
    for (i = 0;; i++) {
        int el = hlm_json_element(&vec, arr, i);
        char nm[64];
        int t;
        if (el < 0) return -1;
        t = hlm_json_member(&vec, el, "Name");
        if (t < 0 || hlm_json_string(&vec, t, nm, sizeof(nm)) == (size_t)-1)
            continue;
        if (strcmp(nm, name) == 0) {
            t = hlm_json_member(&vec, el, "Jws");
            return hlm_json_string(&vec, t, out, cap) == (size_t)-1 ? -1 : 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* mock ports                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *method;
    const char *path;        /* expected, relative to BASE_URL, exact match */
    const char *body_substr; /* NULL = expect no body; "" = any body        */
    const char *idem;        /* NULL = expect none; else exact              */
    int resp_status;
    const char *resp_body;
    int retry_after;         /* -1 = no header */
} mock_step;

typedef struct {
    const mock_step *steps;
    int count;
    int next;
    int fail_transport; /* 1 => every send fails, steps untouched */
} mock_http;

static int mock_send(void *user, const hlm_http_request *req,
                     hlm_http_response *resp)
{
    mock_http *m = (mock_http *)user;
    const mock_step *s;
    size_t base_len = strlen(BASE_URL);
    size_t len;

    if (m->fail_transport) return HLM_E_HTTP;

    checks++;
    if (m->next >= m->count) {
        failures++;
        printf("FAIL mock: unexpected request %s %s\n", req->method, req->url);
        return HLM_E_HTTP;
    }
    s = &m->steps[m->next++];

    CHECK(strcmp(req->method, s->method) == 0, "mock: method");
    CHECK(strncmp(req->url, BASE_URL, base_len) == 0, "mock: base url");
    if (strcmp(req->url + base_len, s->path) != 0) {
        failures++;
        checks++;
        printf("FAIL mock: path\n  want %s\n  got  %s\n", s->path,
               req->url + base_len);
    }
    CHECK(req->api_key != NULL && strcmp(req->api_key, API_KEY) == 0,
          "mock: X-API-KEY");
    CHECK(req->correlation_id != NULL && strlen(req->correlation_id) == 32,
          "mock: correlation id");

    if (s->idem != NULL && strcmp(s->idem, "*") == 0) {
        CHECK(req->idempotency_key != NULL, "mock: some idempotency key");
    } else if (s->idem != NULL) {
        CHECK(req->idempotency_key != NULL &&
                  strcmp(req->idempotency_key, s->idem) == 0,
              "mock: idempotency key");
    } else {
        CHECK(req->idempotency_key == NULL, "mock: no idempotency key");
    }

    if (s->body_substr == NULL) {
        CHECK(req->body == NULL, "mock: no body");
    } else if (s->body_substr[0] != '\0') {
        CHECK(req->body != NULL && strstr(req->body, s->body_substr) != NULL,
              "mock: body content");
    }

    len = strlen(s->resp_body);
    if (len > resp->body_cap) return HLM_E_BUFFER;
    memcpy(resp->body, s->resp_body, len);
    resp->body_len = len;
    resp->status = s->resp_status;
    resp->retry_after_seconds = s->retry_after;
    return HLM_OK;
}

typedef struct {
    char data[8192];
    size_t len;
    int writes;
} mock_store;

static int store_read(void *user, char *buf, size_t cap)
{
    mock_store *s = (mock_store *)user;
    if (s->len == 0) return 0;
    if (s->len > cap) return HLM_E_BUFFER;
    memcpy(buf, s->data, s->len);
    return (int)s->len;
}

static int store_write(void *user, const char *data, size_t len)
{
    mock_store *s = (mock_store *)user;
    if (len >= sizeof(s->data)) return HLM_E_STORAGE;
    memcpy(s->data, data, len);
    s->data[len] = '\0';
    s->len = len;
    s->writes++;
    return HLM_OK;
}

static void store_preload(mock_store *s, const char *jws)
{
    s->len = strlen(jws);
    memcpy(s->data, jws, s->len + 1);
    s->writes = 0;
}

static int64_t g_fake_now;
static int64_t fake_clock_now(void *user)
{
    (void)user;
    return g_fake_now;
}

static unsigned g_slept_ms;
static int g_sleeps;
static void fake_sleep(void *user, unsigned ms)
{
    (void)user;
    g_slept_ms += ms;
    g_sleeps++;
}

static int64_t g_trusted_now;
static int g_timesync_ok;
static int fake_timesync(void *user, int64_t *out)
{
    (void)user;
    if (!g_timesync_ok) return HLM_E_HTTP;
    *out = g_trusted_now;
    return HLM_OK;
}

/* one static client: the struct holds two 16KB buffers */
static hlm_client g_client;

static void setup(hlm_client *c, mock_http *http, mock_store *store,
                  int64_t now, int use_timesync, const char *product_id,
                  const char *machine_id)
{
    hlm_client_cfg cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.base_url = BASE_URL;
    cfg.product_id = product_id != NULL ? product_id : PRODUCT_ID;
    cfg.client_api_key = API_KEY;
    cfg.format = HLM_ALG_RS256;
    cfg.keys = keys;
    cfg.key_count = key_count;
    cfg.machine_id = machine_id != NULL ? machine_id : MACHINE_ID;
    cfg.machine_name = MACHINE_NAME;
    cfg.crypto = hlm_crypto_portable();
    cfg.clock.now = fake_clock_now;
    cfg.sleep.sleep_ms = fake_sleep;
    if (use_timesync) cfg.timesync.now = fake_timesync;
    if (http != NULL) {
        cfg.http.send = mock_send;
        cfg.http.user = http;
    }
    if (store != NULL) {
        cfg.storage.read = store_read;
        cfg.storage.write = store_write;
        cfg.storage.user = store;
    }

    g_fake_now = now;
    g_slept_ms = 0;
    g_sleeps = 0;

    CHECK(hlm_client_init(c, &cfg) == HLM_OK, "client init");
}

/* canonical step lists ------------------------------------------------ */

#define IDEM_COMPUTER "computer:" MACHINE_ID ":" MACHINE_NAME
#define IDEM_LICENSE "license:" PC_ID ":" PRODUCT_ID
#define GET_COMPUTER_PATH "computer?macAddress=" MACHINE_ID
#define GET_LICENSE_PATH                                                     \
    "license?computer=" PC_ID "&product=" PRODUCT_ID "&validDays=90&format=jws"
#define COMPUTER_JSON "{\"id\":\"" PC_ID "\",\"name\":\"" MACHINE_NAME       \
                      "\",\"macAddress\":\"" MACHINE_ID "\"}"

#define STEP_POST_COMPUTER(st)                                               \
    { "POST", "computer", "\"MacAddress\":\"" MACHINE_ID "\"",               \
      IDEM_COMPUTER, st, "", -1 }
#define STEP_GET_COMPUTER                                                    \
    { "GET", GET_COMPUTER_PATH, NULL, NULL, 200, COMPUTER_JSON, -1 }
#define STEP_POST_LICENSE(st)                                                \
    { "POST", "license",                                                     \
      "{\"Product\":\"" PRODUCT_ID "\",\"Computer\":\"" PC_ID "\"}",         \
      IDEM_LICENSE, st, "", -1 }
#define STEP_GET_LICENSE(jws)                                                \
    { "GET", GET_LICENSE_PATH, NULL, NULL, 200, jws, -1 }

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

/* OnInstall_...ShouldWriteItOnDisk + OnLaunch_ShouldAlways_SetStatus +
 * deviceId_Should_includeMachineName + idempotency-key format */
static void test_check_full_chain(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        STEP_GET_LICENSE(jws_trial),
    };
    mock_http http = { steps, 4, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    setup(&g_client, &http, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "full chain: ok");
    CHECK(g_client.status == HLM_STATUS_VALID_TRIAL, "full chain: status set");
    CHECK(strcmp(g_client.license.id, LICENSE_ID) == 0, "full chain: license id");
    CHECK(store.writes == 1, "full chain: license written to disk");
    CHECK(strcmp(store.data, jws_trial) == 0, "full chain: verbatim cache");
    CHECK(http.next == 4, "full chain: all steps consumed");
}

/* LicenseEndPoint_WhenPostingExistingLic_ShouldReturnConflictStatus:
 * 409 on POST computer AND POST license must both count as success */
static void test_conflict_is_success(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(409),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(409),
        STEP_GET_LICENSE(jws_paid),
    };
    mock_http http = { steps, 4, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    setup(&g_client, &http, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "409s: ok");
    CHECK(g_client.status == HLM_STATUS_VALID, "409s: valid");
    CHECK(http.next == 4, "409s: all steps consumed");
}

/* offline launch with a good cached license: zero HTTP requests */
static void test_cached_offline(void)
{
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_paid);
    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "cached offline: ok");
    CHECK(g_client.status == HLM_STATUS_VALID, "cached offline: valid");
    CHECK(store.writes == 0, "cached offline: nothing rewritten");
}

/* OnLaunchFile_IfFileIsModified_ShouldFailToVerify -> refetch from server */
static void test_tampered_cache_refetches(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        STEP_GET_LICENSE(jws_trial),
    };
    mock_http http = { steps, 4, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_tampered);
    setup(&g_client, &http, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "tampered: refetched ok");
    CHECK(g_client.status == HLM_STATUS_VALID_TRIAL, "tampered: fresh status");
    CHECK(http.next == 4, "tampered: full chain ran");
    CHECK(store.writes == 1, "tampered: cache replaced");
}

/* OnLaunch_IfLicExpired_ShouldGetNewOne */
static void test_expired_cache_refetches(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        STEP_GET_LICENSE(jws_paid), /* paid file expires 2026-12-01 */
    };
    mock_http http = { steps, 4, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_trial); /* trial file expires 2026-10-08 */
    setup(&g_client, &http, &store, T_2026_11_01, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "expired cache: ok");
    CHECK(g_client.status == HLM_STATUS_VALID, "expired cache: renewed");
    CHECK(http.next == 4, "expired cache: full chain ran");
}

/* expired cache + no connectivity: surface the verified-but-expired license */
static void test_expired_cache_offline(void)
{
    mock_http http = { NULL, 0, 0, 1 /* transport always fails */ };
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_trial);
    setup(&g_client, &http, &store, T_2026_11_01, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "expired offline: surfaced");
    CHECK(g_client.status == HLM_STATUS_EXPIRED, "expired offline: Expired");
    CHECK(g_client.has_license == 1, "expired offline: license retained");
}

/* OnLaunch_IfProductNameMismatch_ShouldFailToVerify */
static void test_product_mismatch(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        { "POST", "license",
          "{\"Product\":\"PRD_OTHER\",\"Computer\":\"" PC_ID "\"}",
          "license:" PC_ID ":PRD_OTHER", 201, "", -1 },
        { "GET",
          "license?computer=" PC_ID
          "&product=PRD_OTHER&validDays=90&format=jws",
          NULL, NULL, 200, jws_trial, -1 }, /* server returns wrong product */
    };
    mock_http http = { steps, 4, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, "PRD_OTHER", NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_PRODUCT_MISMATCH,
          "product mismatch: rejected");
}

/* OnLaunch_IfComputerNameMismatch_ShouldFailToVerify */
static void test_computer_mismatch(void)
{
    static const char OTHER[] = "OTHERMACHINE0000000000000000000000000000000000000000";
    const mock_step steps[] = {
        { "POST", "computer", "\"MacAddress\":\"OTHERMACHINE", "*", 201, "", -1 },
        { "GET", "computer?macAddress=OTHERMACHINE0000000000000000000000000000000000000000",
          NULL, NULL, 200, COMPUTER_JSON, -1 },
        { "POST", "license", "", "*", 201, "", -1 },
        STEP_GET_LICENSE(jws_trial), /* license is bound to MACHINE_ID */
    };
    mock_http http = { steps, 4, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, OTHER);
    /* idempotency values differ from canonical: skip exact idem assertions */
    http.steps = steps;
    CHECK(hlm_client_check(&g_client) == HLM_E_COMPUTER_MISMATCH,
          "computer mismatch: rejected");
}

/* OnLaunch_AfterCustomerUpdatedProductKey_ShouldGrantAccess */
static void test_activate(void)
{
    const mock_step steps[] = {
        { "PATCH", "license",
          "{\"License\":\"" LICENSE_ID "\",\"Code\":\"RCPT-123\"}",
          NULL, 204, "", -1 },
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(409),
        STEP_GET_LICENSE(jws_paid),
    };
    mock_http http = { steps, 5, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_trial);
    setup(&g_client, &http, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_activate(&g_client, "RCPT-123") == HLM_OK, "activate: ok");
    CHECK(g_client.status == HLM_STATUS_VALID, "activate: granted access");
    CHECK(http.next == 5, "activate: patch then refresh");
    CHECK(strcmp(store.data, jws_paid) == 0, "activate: paid file cached");
}

/* PatchLicenseWithReceiptHandler: 404 -> re-POST license -> retry the patch */
static void test_activate_404_recreates(void)
{
    const mock_step steps[] = {
        { "PATCH", "license", "\"Code\":\"RCPT-123\"", NULL, 404, "", -1 },
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        STEP_GET_LICENSE(jws_trial),
        { "PATCH", "license", "\"Code\":\"RCPT-123\"", NULL, 204, "", -1 },
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(409),
        STEP_GET_LICENSE(jws_paid),
    };
    mock_http http = { steps, 10, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_trial);
    setup(&g_client, &http, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_activate(&g_client, "RCPT-123") == HLM_OK,
          "activate 404: recovered");
    CHECK(g_client.status == HLM_STATUS_VALID, "activate 404: valid");
    CHECK(http.next == 10, "activate 404: full recreate chain");
}

/* OnUninstall_*: PATCH Code:null, refetch, cache lands in unregistered state;
 * the chain uses the HARDWARE machine id (cfg), never the cached file's. */
static void test_deactivate(void)
{
    const mock_step steps[] = {
        { "PATCH", "license",
          "{\"License\":\"" LICENSE_ID "\",\"Code\":null}", NULL, 204, "", -1 },
        STEP_POST_COMPUTER(409),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(409),
        STEP_GET_LICENSE(jws_unregistered),
    };
    mock_http http = { steps, 5, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_paid);
    setup(&g_client, &http, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_deactivate(&g_client) == HLM_OK, "deactivate: ok");
    CHECK(g_client.status == HLM_STATUS_RECEIPT_UNREGISTERED,
          "deactivate: unregistered status");
    CHECK(strcmp(store.data, jws_unregistered) == 0,
          "deactivate: file in unregistered state");
    CHECK(http.next == 5, "deactivate: patch then refetch");
}

/* OnUninstall_WhenNoLicFileOnDisk_ShouldSucceedViaApiChain */
static void test_deactivate_without_cache(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(409),
        STEP_GET_LICENSE(jws_paid),
        { "PATCH", "license", "\"Code\":null", NULL, 204, "", -1 },
        STEP_POST_COMPUTER(409),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(409),
        STEP_GET_LICENSE(jws_unregistered),
    };
    mock_http http = { steps, 9, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    setup(&g_client, &http, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_deactivate(&g_client) == HLM_OK, "deactivate no cache: ok");
    CHECK(g_client.status == HLM_STATUS_RECEIPT_UNREGISTERED,
          "deactivate no cache: unregistered");
    CHECK(http.next == 9, "deactivate no cache: api chain");
}

/* ApiHttp: 401 is terminal, never retried */
static void test_auth_error_no_retry(void)
{
    const mock_step steps[] = {
        { "POST", "computer", "", IDEM_COMPUTER, 401, "", -1 },
    };
    mock_http http = { steps, 1, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_AUTH, "401: HLM_E_AUTH");
    CHECK(http.next == 1, "401: exactly one attempt");
    CHECK(g_sleeps == 0, "401: no backoff");
}

/* ApiHttp: 429 honors Retry-After, then succeeds */
static void test_retry_after(void)
{
    const mock_step steps[] = {
        { "POST", "computer", "", IDEM_COMPUTER, 429, "", 1 },
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        STEP_GET_LICENSE(jws_trial),
    };
    mock_http http = { steps, 5, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "429: recovered");
    CHECK(http.next == 5, "429: retried");
    CHECK(g_slept_ms == 1000, "429: waited Retry-After seconds");
}

/* ApiHttp: 5xx retries with exponential backoff (200, 400) */
static void test_retry_500(void)
{
    const mock_step steps[] = {
        { "POST", "computer", "", IDEM_COMPUTER, 500, "", -1 },
        { "POST", "computer", "", IDEM_COMPUTER, 500, "", -1 },
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        STEP_GET_LICENSE(jws_trial),
    };
    mock_http http = { steps, 6, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "500x2: recovered");
    CHECK(http.next == 6, "500x2: three attempts");
    CHECK(g_slept_ms == 200 + 400, "500x2: exponential backoff");
}

/* ApiHttp: 501 is NOT transient */
static void test_no_retry_501(void)
{
    const mock_step steps[] = {
        { "POST", "computer", "", IDEM_COMPUTER, 501, "", -1 },
    };
    mock_http http = { steps, 1, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_API, "501: HLM_E_API");
    CHECK(http.next == 1, "501: single attempt");
    CHECK(g_sleeps == 0, "501: no backoff");
}

/* TimeSyncDiagnostic concept: a rolled-back local clock cannot resurrect a
 * lapsed trial when the trusted time source disagrees. Uses the legacy
 * (status-less) license so the client's own date rules decide. */
static void test_clock_tamper_detected(void)
{
    mock_store store = { {0}, 0, 0 };

    /* honest run first: local clock inside the trial -> ValidTrial */
    store_preload(&store, jws_legacy);
    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "tamper: baseline ok");
    CHECK(g_client.status == HLM_STATUS_VALID_TRIAL, "tamper: baseline trial");

    /* tampered run: local clock says 07-10 but trusted time says 08-15 */
    store_preload(&store, jws_legacy);
    setup(&g_client, NULL, &store, T_2026_07_10, 1, NULL, NULL);
    g_timesync_ok = 1;
    g_trusted_now = T_2026_08_15;
    CHECK(hlm_client_check(&g_client) == HLM_OK, "tamper: check ok");
    CHECK(g_client.status == HLM_STATUS_INVALID_TRIAL,
          "tamper: trusted time wins over local clock");
}

/* timesync unavailable -> GET DateTime fallback decides the status */
static void test_server_time_fallback(void)
{
    const mock_step steps[] = {
        { "GET", "DateTime", NULL, NULL, 200, "\"2026-08-15T00:00:00Z\"", -1 },
    };
    mock_http http = { steps, 1, 0, 0 };
    mock_store store = { {0}, 0, 0 };

    store_preload(&store, jws_legacy);
    setup(&g_client, &http, &store, T_2026_07_10, 1, NULL, NULL);
    g_timesync_ok = 0; /* cascade: timesync fails -> API DateTime */
    CHECK(hlm_client_check(&g_client) == HLM_OK, "server time: ok");
    CHECK(g_client.status == HLM_STATUS_INVALID_TRIAL,
          "server time: API DateTime decided");
    CHECK(http.next == 1, "server time: DateTime endpoint called");
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: hlm_flow_tests <vectors.json>\n");
        return 2;
    }
    if (load_vectors(argv[1]) != 0) {
        printf("cannot load vectors\n");
        return 2;
    }
    if (get_case_jws("rs256-trial-valid", jws_trial, sizeof(jws_trial)) != 0 ||
        get_case_jws("rs256-paid-valid", jws_paid, sizeof(jws_paid)) != 0 ||
        get_case_jws("rs256-receipt-unregistered", jws_unregistered,
                     sizeof(jws_unregistered)) != 0 ||
        get_case_jws("rs256-legacy-trial", jws_legacy, sizeof(jws_legacy)) != 0 ||
        get_case_jws("rs256-tampered-payload", jws_tampered,
                     sizeof(jws_tampered)) != 0) {
        printf("missing vector cases\n");
        return 2;
    }

    test_check_full_chain();
    test_conflict_is_success();
    test_cached_offline();
    test_tampered_cache_refetches();
    test_expired_cache_refetches();
    test_expired_cache_offline();
    test_product_mismatch();
    test_computer_mismatch();
    test_activate();
    test_activate_404_recreates();
    test_deactivate();
    test_deactivate_without_cache();
    test_auth_error_no_retry();
    test_retry_after();
    test_retry_500();
    test_no_retry_501();
    test_clock_tamper_detected();
    test_server_time_fallback();

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
