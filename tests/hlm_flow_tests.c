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
#include "hymma/hlm_ffi.h"
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
    hlm_net_failure net_failure; /* cause a failing transport reports;
                                    HLM_NET_NONE => leave the client's preset */
    int sends;          /* every send, including failed ones */
} mock_http;

static int mock_send(void *user, const hlm_http_request *req,
                     hlm_http_response *resp)
{
    mock_http *m = (mock_http *)user;
    const mock_step *s;
    size_t base_len = strlen(BASE_URL);
    size_t len;

    m->sends++;
    if (m->fail_transport) {
        if (m->net_failure != HLM_NET_NONE) resp->failure = m->net_failure;
        return HLM_E_HTTP;
    }

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
    int fail_write; /* 1 => every write fails (disk full, read-only folder) */
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
    if (s->fail_write) return HLM_E_STORAGE;
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

/* Server refusals classify into dedicated errors so wrappers can raise
 * meaningful exceptions, and the server's human-readable detail is captured. */
static void test_trial_quota_classified(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        { "POST", "license", "", IDEM_LICENSE, 402,
          "{\"error\":\"trial_quota\",\"current\":250,\"limit\":250}", -1 },
    };
    mock_http http = { steps, 3, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_TRIAL_QUOTA,
          "quota refusal: classified");
    CHECK(strcmp(g_client.last_error, "trial_quota") == 0,
          "quota refusal: detail captured");
}

static void test_paid_format_required_classified(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        { "GET", GET_LICENSE_PATH, NULL, NULL, 402,
          "{\"type\":\"https://license-management.com/errors/embedded-format-requires-receipt\","
          "\"title\":\"Embedded license format requires an active paid receipt\","
          "\"status\":402,\"detail\":\"Register a valid receipt code and try again.\"}", -1 },
    };
    mock_http http = { steps, 4, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_PAID_FORMAT_REQUIRED,
          "format refusal: classified");
    CHECK(strstr(g_client.last_error, "receipt code") != NULL,
          "format refusal: server detail captured");
}

static void test_plan_limit_classified(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        { "POST", "license", "", IDEM_LICENSE, 402,
          "{\"error\":\"ALU limit exceeded\",\"current\":50,\"limit\":50}", -1 },
    };
    mock_http http = { steps, 3, 0, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_PLAN_LIMIT,
          "plan limit: classified");
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
/* network diagnosis                                                   */
/* ------------------------------------------------------------------ */

/* Expected messages are the .NET SDK's NetworkUnavailableException.MessageFor
 * wording (LicenseManagement.EndUser 3.5.0), with host = api.test. */
#define MSG_DNS                                                              \
    "This computer's network could not find api.test. A company DNS filter " \
    "or firewall is probably blocking it. Ask your IT team to allow "        \
    "api.test, or install the license file by hand."
#define MSG_TLS                                                              \
    "A secure connection to api.test could not be set up. A proxy or "       \
    "security product may be inspecting HTTPS traffic. Ask your IT team to " \
    "allow api.test, or install the license file by hand."
#define MSG_PROXY                                                            \
    "The network proxy refused the connection to api.test. Ask your IT "     \
    "team to allow api.test, or install the license file by hand."
#define MSG_TIMEOUT                                                          \
    "api.test did not answer in time. The network may be slow or blocking "  \
    "it. Try again, or install the license file by hand."
#define MSG_CONNECT                                                          \
    "Could not connect to api.test. Check the internet connection and "      \
    "firewall, or install the license file by hand."

/* WinHTTP / Winsock error numbers -> cause (values from winhttp.h/winerror.h) */
static void test_net_failure_from_winhttp(void)
{
    CHECK(hlm_net_failure_from_winhttp(12007) == HLM_NET_NAME_RESOLUTION,
          "winhttp 12007 NAME_NOT_RESOLVED -> DNS");
    CHECK(hlm_net_failure_from_winhttp(11004) == HLM_NET_NAME_RESOLUTION,
          "winsock 11004 WSANO_DATA (the reviewer's error) -> DNS");
    CHECK(hlm_net_failure_from_winhttp(11001) == HLM_NET_NAME_RESOLUTION,
          "winsock 11001 WSAHOST_NOT_FOUND -> DNS");
    CHECK(hlm_net_failure_from_winhttp(12175) == HLM_NET_SECURE_CONNECTION,
          "winhttp 12175 SECURE_FAILURE -> TLS");
    CHECK(hlm_net_failure_from_winhttp(12157) == HLM_NET_SECURE_CONNECTION,
          "winhttp 12157 SECURE_CHANNEL_ERROR -> TLS");
    CHECK(hlm_net_failure_from_winhttp(12045) == HLM_NET_SECURE_CONNECTION,
          "winhttp 12045 SECURE_INVALID_CA (inspecting proxy) -> TLS");
    CHECK(hlm_net_failure_from_winhttp(12002) == HLM_NET_TIMEOUT,
          "winhttp 12002 TIMEOUT -> timeout");
    CHECK(hlm_net_failure_from_winhttp(12029) == HLM_NET_CONNECTION,
          "winhttp 12029 CANNOT_CONNECT -> connection");
    CHECK(hlm_net_failure_from_winhttp(12030) == HLM_NET_CONNECTION,
          "winhttp 12030 CONNECTION_ERROR -> connection");
    CHECK(hlm_net_failure_from_winhttp(12167) == HLM_NET_PROXY,
          "winhttp 12167 UNABLE_TO_DOWNLOAD_SCRIPT (PAC) -> proxy");
    CHECK(hlm_net_failure_from_winhttp(12180) == HLM_NET_PROXY,
          "winhttp 12180 AUTODETECTION_FAILED (WPAD) -> proxy");
    CHECK(hlm_net_failure_from_winhttp(0) == HLM_NET_UNKNOWN,
          "winhttp 0 -> unknown");
    CHECK(hlm_net_failure_from_winhttp(5) == HLM_NET_UNKNOWN,
          "winhttp 5 ACCESS_DENIED -> unknown");
}

/* CURLcode -> cause (values from curl.h) */
static void test_net_failure_from_curl(void)
{
    CHECK(hlm_net_failure_from_curl(6) == HLM_NET_NAME_RESOLUTION,
          "curl 6 COULDNT_RESOLVE_HOST -> DNS");
    CHECK(hlm_net_failure_from_curl(5) == HLM_NET_PROXY,
          "curl 5 COULDNT_RESOLVE_PROXY -> proxy");
    CHECK(hlm_net_failure_from_curl(97) == HLM_NET_PROXY, "curl 97 PROXY -> proxy");
    CHECK(hlm_net_failure_from_curl(7) == HLM_NET_CONNECTION,
          "curl 7 COULDNT_CONNECT -> connection");
    CHECK(hlm_net_failure_from_curl(56) == HLM_NET_CONNECTION,
          "curl 56 RECV_ERROR -> connection");
    CHECK(hlm_net_failure_from_curl(28) == HLM_NET_TIMEOUT,
          "curl 28 OPERATION_TIMEDOUT -> timeout");
    CHECK(hlm_net_failure_from_curl(35) == HLM_NET_SECURE_CONNECTION,
          "curl 35 SSL_CONNECT_ERROR -> TLS");
    CHECK(hlm_net_failure_from_curl(60) == HLM_NET_SECURE_CONNECTION,
          "curl 60 PEER_FAILED_VERIFICATION -> TLS");
    CHECK(hlm_net_failure_from_curl(0) == HLM_NET_UNKNOWN, "curl 0 -> unknown");
    CHECK(hlm_net_failure_from_curl(1) == HLM_NET_UNKNOWN,
          "curl 1 UNSUPPORTED_PROTOCOL -> unknown");
}

static void test_net_messages(void)
{
    char msg[512], tiny[16];

    CHECK(hlm_net_message(HLM_NET_NAME_RESOLUTION, "api.test", msg,
                          sizeof(msg)) == HLM_OK &&
              strcmp(msg, MSG_DNS) == 0,
          "net message: DNS names the host to allow");
    CHECK(hlm_net_message(HLM_NET_SECURE_CONNECTION, "api.test", msg,
                          sizeof(msg)) == HLM_OK &&
              strcmp(msg, MSG_TLS) == 0,
          "net message: TLS");
    CHECK(hlm_net_message(HLM_NET_PROXY, "api.test", msg, sizeof(msg)) ==
                  HLM_OK &&
              strcmp(msg, MSG_PROXY) == 0,
          "net message: proxy");
    CHECK(hlm_net_message(HLM_NET_TIMEOUT, "api.test", msg, sizeof(msg)) ==
                  HLM_OK &&
              strcmp(msg, MSG_TIMEOUT) == 0,
          "net message: timeout");
    CHECK(hlm_net_message(HLM_NET_CONNECTION, "api.test", msg, sizeof(msg)) ==
                  HLM_OK &&
              strcmp(msg, MSG_CONNECT) == 0,
          "net message: connection");
    CHECK(hlm_net_message(HLM_NET_UNKNOWN, "api.test", msg, sizeof(msg)) ==
                  HLM_OK &&
              strcmp(msg, MSG_CONNECT) == 0,
          "net message: unknown reads as could-not-connect");
    CHECK(hlm_net_message(HLM_NET_NAME_RESOLUTION, "api.test", tiny,
                          sizeof(tiny)) == HLM_E_BUFFER &&
              strlen(tiny) == sizeof(tiny) - 1,
          "net message: truncation reported, still terminated");

    CHECK(strcmp(hlm_net_failure_str(HLM_NET_NAME_RESOLUTION),
                 "NameResolution") == 0 &&
              strcmp(hlm_net_failure_str(HLM_NET_SECURE_CONNECTION),
                     "SecureConnection") == 0 &&
              strcmp(hlm_net_failure_str(HLM_NET_PROXY), "Proxy") == 0 &&
              strcmp(hlm_net_failure_str(HLM_NET_TIMEOUT), "Timeout") == 0 &&
              strcmp(hlm_net_failure_str(HLM_NET_CONNECTION), "Connection") == 0 &&
              strcmp(hlm_net_failure_str(HLM_NET_UNKNOWN), "Unknown") == 0 &&
              strcmp(hlm_net_failure_str(HLM_NET_NONE), "None") == 0,
          "net failure names match the .NET NetworkFailureReason");
}

/* The transport's cause reaches the caller: HLM_E_HTTP still, plus the
 * reason and a message naming the host, for every cause. */
static void test_transport_failure_is_explained(void)
{
    static const struct {
        hlm_net_failure port_says;
        hlm_net_failure expect;
        const char *message;
    } cases[] = {
        { HLM_NET_NAME_RESOLUTION, HLM_NET_NAME_RESOLUTION, MSG_DNS },
        { HLM_NET_SECURE_CONNECTION, HLM_NET_SECURE_CONNECTION, MSG_TLS },
        { HLM_NET_PROXY, HLM_NET_PROXY, MSG_PROXY },
        { HLM_NET_TIMEOUT, HLM_NET_TIMEOUT, MSG_TIMEOUT },
        { HLM_NET_CONNECTION, HLM_NET_CONNECTION, MSG_CONNECT },
        /* a custom port that reports nothing: cause unknown, generic text */
        { HLM_NET_NONE, HLM_NET_UNKNOWN, MSG_CONNECT },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        mock_http http = { NULL, 0, 0, 1, HLM_NET_NONE, 0 };
        http.net_failure = cases[i].port_says;

        setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
        CHECK(hlm_client_check(&g_client) == HLM_E_HTTP,
              "transport failure: still HLM_E_HTTP");
        CHECK(g_client.last_net_failure == cases[i].expect,
              "transport failure: cause recorded");
        if (strcmp(g_client.last_error, cases[i].message) != 0) {
            failures++;
            printf("FAIL transport failure message\n  want %s\n  got  %s\n",
                   cases[i].message, g_client.last_error);
        }
        checks++;
        CHECK(http.sends == 3, "transport failure: still retried 3 times");
    }
}

/* Offline with a cached file: check() succeeds from the cache, and the
 * cause stays visible so a UI can offer the by-hand install. */
static void test_offline_fallback_keeps_cause(void)
{
    mock_http http = { NULL, 0, 0, 1, HLM_NET_NAME_RESOLUTION, 0 };
    mock_store store = { {0}, 0, 0, 0 };

    store_preload(&store, jws_trial);
    setup(&g_client, &http, &store, T_2026_11_01, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK, "offline fallback: ok");
    CHECK(g_client.status == HLM_STATUS_EXPIRED, "offline fallback: Expired");
    CHECK(g_client.last_net_failure == HLM_NET_NAME_RESOLUTION,
          "offline fallback: DNS cause visible");
}

/* A proxy's 407 is a network refusal, not an API answer: Proxy, no retry. */
static void test_proxy_407(void)
{
    const mock_step steps[] = {
        { "POST", "computer", "", IDEM_COMPUTER, 407, "", -1 },
    };
    mock_http http = { steps, 1, 0, 0, HLM_NET_NONE, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_HTTP, "407: network error");
    CHECK(g_client.last_net_failure == HLM_NET_PROXY, "407: proxy");
    CHECK(strcmp(g_client.last_error, MSG_PROXY) == 0, "407: proxy message");
    CHECK(http.next == 1 && g_sleeps == 0, "407: not retried");
}

/* A later call that reaches the server does not report the old failure. */
static void test_success_clears_cause(void)
{
    const mock_step steps[] = {
        STEP_POST_COMPUTER(201),
        STEP_GET_COMPUTER,
        STEP_POST_LICENSE(201),
        STEP_GET_LICENSE(jws_trial),
    };
    mock_http http = { steps, 4, 0, 1, HLM_NET_TIMEOUT, 0 };

    setup(&g_client, &http, NULL, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_E_HTTP, "clears: first fails");
    CHECK(g_client.last_net_failure == HLM_NET_TIMEOUT, "clears: timeout");
    http.fail_transport = 0;
    CHECK(hlm_client_check(&g_client) == HLM_OK, "clears: then succeeds");
    CHECK(g_client.last_net_failure == HLM_NET_NONE, "clears: cause cleared");
}

#if defined(_WIN32)
/* The real WinHTTP port against causes this machine can produce on its own:
 * nothing listens on 127.0.0.1:1, and .invalid never resolves (RFC 2606). */
static void test_winhttp_real_causes(void)
{
    static const struct {
        const char *base_url;
        hlm_net_failure expect;
        const char *host_in_message;
    } cases[] = {
        { "http://127.0.0.1:1/api/", HLM_NET_CONNECTION, "127.0.0.1" },
        { "https://hlm-test-host.invalid/api/", HLM_NET_NAME_RESOLUTION,
          "hlm-test-host.invalid" },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        hlm_client_cfg cfg;
        int r;

        memset(&cfg, 0, sizeof(cfg));
        cfg.base_url = cases[i].base_url;
        cfg.product_id = PRODUCT_ID;
        cfg.client_api_key = API_KEY;
        cfg.keys = keys;
        cfg.key_count = key_count;
        cfg.machine_id = MACHINE_ID;
        cfg.machine_name = MACHINE_NAME;
        cfg.crypto = hlm_crypto_portable();
        cfg.http = hlm_http_winhttp();
        cfg.sleep.sleep_ms = fake_sleep;
        CHECK(hlm_client_init(&g_client, &cfg) == HLM_OK, "winhttp: init");
        r = hlm_client_check(&g_client);
        CHECK(r == HLM_E_HTTP, "winhttp: transport error");
        if (g_client.last_net_failure != cases[i].expect) {
            failures++;
            printf("FAIL winhttp %s: cause %s, want %s\n", cases[i].base_url,
                   hlm_net_failure_str(g_client.last_net_failure),
                   hlm_net_failure_str(cases[i].expect));
        }
        checks++;
        CHECK(strstr(g_client.last_error, cases[i].host_in_message) != NULL,
              "winhttp: message names the host");
    }
}
#endif

/* ------------------------------------------------------------------ */
/* license file installed by hand                                      */
/* ------------------------------------------------------------------ */

static void test_import_genuine_installs(void)
{
    mock_store store = { {0}, 0, 0, 0 };

    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_import(&g_client, jws_paid, strlen(jws_paid)) ==
              HLM_IMPORT_INSTALLED,
          "import genuine: installed");
    CHECK(store.writes == 1 && strcmp(store.data, jws_paid) == 0,
          "import genuine: written verbatim");
    CHECK(g_client.has_license && g_client.status == HLM_STATUS_VALID,
          "import genuine: adopted, Valid");
    CHECK(strcmp(g_client.last_error, "License file installed.") == 0,
          "import genuine: message");

    /* and the next offline launch accepts what was installed */
    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_check(&g_client) == HLM_OK &&
              g_client.status == HLM_STATUS_VALID,
          "import genuine: next launch reads it");
}

/* what a browser download / mail client wraps around the token */
static void test_import_tolerates_bom_and_newlines(void)
{
    static char wrapped[8300];
    mock_store store = { {0}, 0, 0, 0 };

    snprintf(wrapped, sizeof(wrapped), "\xEF\xBB\xBF\r\n  %s\r\n\r\n", jws_paid);
    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_import(&g_client, wrapped, strlen(wrapped)) ==
              HLM_IMPORT_INSTALLED,
          "import wrapped: installed");
    CHECK(strcmp(store.data, jws_paid) == 0, "import wrapped: token stored");
}

/* Every refusal leaves the existing file exactly as it was. */
static void expect_refused(const char *doc, const char *product_id,
                           const char *machine_id, int expected,
                           const char *msg_substr, const char *name)
{
    mock_store store = { {0}, 0, 0, 0 };
    int r;

    store_preload(&store, jws_trial);
    setup(&g_client, NULL, &store, T_2026_07_10, 0, product_id, machine_id);
    r = hlm_client_import(&g_client, doc, strlen(doc));
    if (r != expected) {
        failures++;
        printf("FAIL %s: got %s, want %s\n", name, hlm_import_result_str(r),
               hlm_import_result_str(expected));
    }
    checks++;
    CHECK(store.writes == 0 && strcmp(store.data, jws_trial) == 0,
          "import refused: existing file untouched");
    CHECK(!g_client.has_license, "import refused: nothing adopted");
    if (strstr(g_client.last_error, msg_substr) == NULL) {
        failures++;
        printf("FAIL %s message: %s\n", name, g_client.last_error);
    }
    checks++;
}

static void test_import_refusals(void)
{
    static const char OTHER[] = "OTHERMACHINE0000000000000000000000000000000000000000";

    expect_refused(jws_tampered, NULL, NULL, HLM_IMPORT_SIGNATURE_INVALID,
                   "wasn't issued for this product's publisher, or it has "
                   "been changed. Download it again.",
                   "import tampered");
    expect_refused(jws_paid, "PRD_OTHER", NULL, HLM_IMPORT_WRONG_PRODUCT,
                   "This license file is for CADshift Nesting, not this one.",
                   "import other product");
    expect_refused(jws_paid, NULL, OTHER, HLM_IMPORT_WRONG_COMPUTER,
                   "This license file is for the computer SHOP-FLOOR-01. "
                   "Download the file for this computer.",
                   "import other computer");
    expect_refused("hello world, this is not a license", NULL, NULL,
                   HLM_IMPORT_NOT_A_LICENSE,
                   "That isn't a license file. Choose the .lic file you "
                   "downloaded.",
                   "import garbage");
    expect_refused("<?xml version=\"1.0\"?><License><Id>LIC_1</Id></License>",
                   NULL, NULL, HLM_IMPORT_NOT_A_LICENSE, "isn't a license file",
                   "import xml license");
    expect_refused("", NULL, NULL, HLM_IMPORT_NOT_A_LICENSE,
                   "isn't a license file", "import empty");
    /* JWS-shaped but its segments do not decode to a license */
    expect_refused("aGVsbG8.d29ybGQ.c2ln", NULL, NULL, HLM_IMPORT_NOT_A_LICENSE,
                   "isn't a license file", "import jws-shaped junk");
}

/* identity v2 machines also accept a file issued to their legacy v1 id —
 * both on import and on the offline launch that reads it afterwards */
static void test_import_legacy_machine_id(void)
{
    static const char V2[] = "V2MACHINEID00000000000000000000000000000000000000000";
    mock_store store = { {0}, 0, 0, 0 };

    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, V2);
    g_client.cfg.machine_id_legacy = MACHINE_ID;
    CHECK(hlm_client_import(&g_client, jws_paid, strlen(jws_paid)) ==
              HLM_IMPORT_INSTALLED,
          "import legacy id: installed");

    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, V2);
    g_client.cfg.machine_id_legacy = MACHINE_ID;
    CHECK(hlm_client_check(&g_client) == HLM_OK &&
              g_client.status == HLM_STATUS_VALID,
          "legacy id: offline launch accepts the file");

    /* without the legacy id the same file is another computer's */
    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, V2);
    CHECK(hlm_client_import(&g_client, jws_paid, strlen(jws_paid)) ==
              HLM_IMPORT_WRONG_COMPUTER,
          "import v2 only: wrong computer");
}

static void test_import_write_failed(void)
{
    mock_store store = { {0}, 0, 0, 1 /* writes fail */ };

    setup(&g_client, NULL, &store, T_2026_07_10, 0, NULL, NULL);
    CHECK(hlm_client_import(&g_client, jws_paid, strlen(jws_paid)) ==
              HLM_IMPORT_WRITE_FAILED,
          "import write failed: reported");
    CHECK(!g_client.has_license, "import write failed: nothing adopted");
    CHECK(strcmp(g_client.last_error, "The license file couldn't be saved.") == 0,
          "import write failed: message");
}

/* the low-level entry point, for what a client cannot express */
static void test_import_low_level(void)
{
    mock_store store = { {0}, 0, 0, 0 };
    hlm_storage st;
    hlm_crypto crypto = hlm_crypto_portable();
    hlm_storage no_storage;
    char es256[8192];
    hlm_license lic;

    st.read = store_read;
    st.write = store_write;
    st.user = &store;
    memset(&no_storage, 0, sizeof(no_storage));

    CHECK(hlm_license_import(jws_paid, strlen(jws_paid), NULL, 0, &crypto,
                             PRODUCT_ID, MACHINE_ID, NULL, &st, NULL) ==
              HLM_IMPORT_NO_PUBLIC_KEY,
          "import: no public key");
    CHECK(store.writes == 0, "import no key: nothing written");

    /* signed with the vendor's EC key, but only the RSA key is trusted */
    CHECK(get_case_jws("es256-paid-valid", es256, sizeof(es256)) == 0,
          "import: es256 vector");
    CHECK(hlm_license_import(es256, strlen(es256), &keys[0], 1, &crypto,
                             PRODUCT_ID, MACHINE_ID, NULL, &st, NULL) ==
              HLM_IMPORT_SIGNATURE_INVALID,
          "import: key of another algorithm/vendor -> signature invalid");

    CHECK(hlm_license_import(jws_paid, strlen(jws_paid), keys, key_count,
                             &crypto, PRODUCT_ID, MACHINE_ID, NULL,
                             &no_storage, NULL) == HLM_E_ARG,
          "import: no storage port is a programming error");

    CHECK(hlm_license_import(jws_paid, strlen(jws_paid), keys, key_count,
                             &crypto, PRODUCT_ID, MACHINE_ID, NULL, &st,
                             &lic) == HLM_IMPORT_INSTALLED &&
              strcmp(lic.id, LICENSE_ID) == 0,
          "import: installed, license returned");

    CHECK(strcmp(hlm_import_result_str(HLM_IMPORT_INSTALLED), "Installed") == 0 &&
              strcmp(hlm_import_result_str(HLM_IMPORT_NOT_A_LICENSE),
                     "NotALicenseFile") == 0 &&
              strcmp(hlm_import_result_str(HLM_IMPORT_NO_PUBLIC_KEY),
                     "NoPublicKey") == 0 &&
              strcmp(hlm_import_result_str(HLM_IMPORT_SIGNATURE_INVALID),
                     "SignatureInvalid") == 0 &&
              strcmp(hlm_import_result_str(HLM_IMPORT_WRONG_PRODUCT),
                     "WrongProduct") == 0 &&
              strcmp(hlm_import_result_str(HLM_IMPORT_WRONG_COMPUTER),
                     "WrongComputer") == 0 &&
              strcmp(hlm_import_result_str(HLM_IMPORT_WRITE_FAILED),
                     "WriteFailed") == 0,
          "import result names match the .NET LicenseImportOutcome");
}

static int read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) return -1;
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (int)n;
}

static int write_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return -1;
    fwrite(data, 1, strlen(data), f);
    return fclose(f);
}

/* Through the FFI and the real file port: a refused file never replaces the
 * one on disk, a genuine one does, and the path is visible to a host UI. */
static void test_import_ffi_file(void)
{
    static char jwks[2048];
    static char got[8192];
    const char *lic_path = "hlm_import_test_cache.lic";
    const char *src_good = "hlm_import_test_good.lic";
    const char *src_bad = "hlm_import_test_bad.lic";
    hlm_ffi_client *fc;
    int t = hlm_json_member(&vec, 0, "RsaJwk");
    size_t n = (size_t)(vec.toks[t].end - vec.toks[t].start);

    memcpy(jwks, vec.src + vec.toks[t].start, n);
    jwks[n] = '\0';

    CHECK(write_file(lic_path, jws_trial) == 0, "ffi import: seed cache");
    CHECK(write_file(src_good, jws_paid) == 0, "ffi import: seed good");
    CHECK(write_file(src_bad, jws_tampered) == 0, "ffi import: seed bad");

    fc = hlm_ffi_create(BASE_URL, PRODUCT_ID, API_KEY, jwks, 1, 0, MACHINE_ID,
                        MACHINE_NAME, lic_path);
    CHECK(fc != NULL, "ffi import: create");
    if (fc == NULL) return;

    CHECK(strcmp(hlm_ffi_license_path(fc), lic_path) == 0,
          "ffi: license path exposed");

    CHECK(hlm_ffi_import_license_file(fc, src_bad) ==
              HLM_IMPORT_SIGNATURE_INVALID,
          "ffi import tampered: refused");
    CHECK(read_file(lic_path, got, sizeof(got)) > 0 &&
              strcmp(got, jws_trial) == 0,
          "ffi import tampered: cache file untouched");

    CHECK(hlm_ffi_import_license_file(fc, "hlm_import_test_missing.lic") ==
              HLM_IMPORT_NOT_A_LICENSE,
          "ffi import missing file: not a license");
    CHECK(strstr(hlm_ffi_last_error_detail(fc), "could not be read") != NULL,
          "ffi import missing file: says why");

    CHECK(hlm_ffi_import_license_file(fc, src_good) == HLM_IMPORT_INSTALLED,
          "ffi import genuine: installed");
    CHECK(read_file(lic_path, got, sizeof(got)) > 0 && strcmp(got, jws_paid) == 0,
          "ffi import genuine: cache replaced");
    CHECK(strcmp(hlm_ffi_last_error_detail(fc), "License file installed.") == 0,
          "ffi import genuine: message");
    CHECK(strcmp(hlm_ffi_import_result_name(HLM_IMPORT_INSTALLED), "Installed") == 0,
          "ffi import result name");
    CHECK(strcmp(hlm_ffi_license_id(fc), LICENSE_ID) == 0,
          "ffi import genuine: license adopted");

    hlm_ffi_destroy(fc);

    /* a cache folder that does not exist: WriteFailed names the path */
    fc = hlm_ffi_create(BASE_URL, PRODUCT_ID, API_KEY, jwks, 1, 0, MACHINE_ID,
                        MACHINE_NAME, "hlm-no-such-dir/sub/cache.lic");
    CHECK(fc != NULL, "ffi import unwritable: create");
    if (fc != NULL) {
        CHECK(hlm_ffi_import_license(fc, jws_paid) == HLM_IMPORT_WRITE_FAILED,
              "ffi import unwritable: write failed");
        CHECK(strcmp(hlm_ffi_last_error_detail(fc),
                     "The license file couldn't be saved to "
                     "hlm-no-such-dir/sub/cache.lic.") == 0,
              "ffi import unwritable: message names the path");
        hlm_ffi_destroy(fc);
    }

    /* no cache configured: nothing to install into */
    fc = hlm_ffi_create(BASE_URL, PRODUCT_ID, API_KEY, jwks, 1, 0, MACHINE_ID,
                        MACHINE_NAME, NULL);
    if (fc != NULL) {
        CHECK(hlm_ffi_import_license(fc, jws_paid) == HLM_E_ARG,
              "ffi import without license_path: HLM_E_ARG");
        CHECK(strcmp(hlm_ffi_license_path(fc), "") == 0,
              "ffi: no license path");
        hlm_ffi_destroy(fc);
    }

    remove(lic_path);
    remove(src_good);
    remove(src_bad);
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
    test_trial_quota_classified();
    test_paid_format_required_classified();
    test_plan_limit_classified();
    test_clock_tamper_detected();
    test_server_time_fallback();

    test_net_failure_from_winhttp();
    test_net_failure_from_curl();
    test_net_messages();
    test_transport_failure_is_explained();
    test_offline_fallback_keeps_cause();
    test_proxy_407();
    test_success_clears_cause();
#if defined(_WIN32)
    test_winhttp_real_causes();
#endif

    test_import_genuine_installs();
    test_import_tolerates_bom_and_newlines();
    test_import_refusals();
    test_import_legacy_machine_id();
    test_import_write_failed();
    test_import_low_level();
    test_import_ffi_file();

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
