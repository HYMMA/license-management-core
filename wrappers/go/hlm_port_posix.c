/* POSIX ports (Linux, macOS, BSDs): libcurl transport, machine identity,
 * sleep, trusted time.
 *
 * HTTP: libcurl is loaded with dlopen() at runtime instead of being linked,
 * so the shared library that language wrappers load stays dependency-free
 * and works against whichever libcurl flavor the distro ships (OpenSSL or
 * GnuTLS). Only ABI-stable, explicitly numbered curl options are used.
 *
 * Machine identity: the stable OS machine id — /etc/machine-id on Linux
 * (systemd/dbus), gethostuuid() on macOS — run through hlm_fingerprint(),
 * the same SHA-256 → Crockford-Base32 pipeline as the Windows/.NET SDK path.
 * (The raw id never leaves the machine; only the hash does.)
 *
 * Trusted time: SNTP to pool.ntp.org (dev builds compiled with
 * -DHLM_DEV_TIMESYNC_ENV may override via HLM_NTP_HOST / HLM_TIMESYNC=off;
 * release builds ignore both); the local clock is trusted only when it agrees
 * with the NTP answer within 1h — the same drift rule as the Windows port
 * and the .NET SDK's TimeSyncDiagnostic. On failure the client falls back
 * to GET DateTime, then the local clock.
 */
#if !defined(_WIN32)

/* Feature-test macros must precede every system include: the port needs
 * POSIX.1-2008 (nanosleep, getaddrinfo, gethostname, strncasecmp) and
 * builds under strict -std=c99, not just gnu99. */
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1 /* gethostuuid and BSD socket details */
#endif

#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "hymma/hlm.h"
#include "hlm_sntp.h"

#define HLM_HTTP_TIMEOUT_MS 15000 /* per request, matches the .NET SDK */

/* ------------------------------------------------------------------ */
/* libcurl transport (dlopen)                                          */
/* ------------------------------------------------------------------ */

/* ABI-stable curl option/info numbers (see curl.h CURLOPT_* macros). */
#define HLM_CURLOPT_WRITEDATA 10001L
#define HLM_CURLOPT_URL 10002L
#define HLM_CURLOPT_POSTFIELDS 10015L
#define HLM_CURLOPT_USERAGENT 10018L
#define HLM_CURLOPT_HTTPHEADER 10023L
#define HLM_CURLOPT_HEADERDATA 10029L
#define HLM_CURLOPT_CUSTOMREQUEST 10036L
#define HLM_CURLOPT_POSTFIELDSIZE 60L
#define HLM_CURLOPT_NOSIGNAL 99L
#define HLM_CURLOPT_TIMEOUT_MS 155L
#define HLM_CURLOPT_CONNECTTIMEOUT_MS 156L
#define HLM_CURLOPT_WRITEFUNCTION 20011L
#define HLM_CURLOPT_HEADERFUNCTION 20079L
#define HLM_CURLINFO_RESPONSE_CODE 2097154L /* CURLINFO_LONG + 2 */

typedef void hlm_CURL;
typedef struct hlm_curl_slist hlm_curl_slist;

typedef struct {
    void *handle;
    hlm_CURL *(*easy_init)(void);
    int (*easy_setopt)(hlm_CURL *, long, ...);
    int (*easy_perform)(hlm_CURL *);
    void (*easy_cleanup)(hlm_CURL *);
    void (*easy_reset)(hlm_CURL *);
    int (*easy_getinfo)(hlm_CURL *, long, ...);
    hlm_curl_slist *(*slist_append)(hlm_curl_slist *, const char *);
    void (*slist_free_all)(hlm_curl_slist *);
} curl_api;

static curl_api g_curl; /* filled exactly once, under g_curl_once */
static pthread_once_t g_curl_once = PTHREAD_ONCE_INIT;

static void curl_load_once(void)
{
    static const char *const NAMES[] = {
        "libcurl.so.4", "libcurl.so", "libcurl-gnutls.so.4",
        "libcurl.4.dylib", "libcurl.dylib"
    };
    int (*global_init)(long) = NULL;
    size_t i;
    void *h = NULL;

    for (i = 0; i < sizeof(NAMES) / sizeof(NAMES[0]) && h == NULL; i++)
        h = dlopen(NAMES[i], RTLD_NOW | RTLD_GLOBAL);
    if (h == NULL) return;

    *(void **)&g_curl.easy_init = dlsym(h, "curl_easy_init");
    *(void **)&g_curl.easy_setopt = dlsym(h, "curl_easy_setopt");
    *(void **)&g_curl.easy_perform = dlsym(h, "curl_easy_perform");
    *(void **)&g_curl.easy_cleanup = dlsym(h, "curl_easy_cleanup");
    *(void **)&g_curl.easy_getinfo = dlsym(h, "curl_easy_getinfo");
    *(void **)&g_curl.slist_append = dlsym(h, "curl_slist_append");
    *(void **)&g_curl.slist_free_all = dlsym(h, "curl_slist_free_all");
    *(void **)&g_curl.easy_reset = dlsym(h, "curl_easy_reset");
    *(void **)&global_init = dlsym(h, "curl_global_init");

    if (g_curl.easy_init == NULL || g_curl.easy_setopt == NULL ||
        g_curl.easy_perform == NULL || g_curl.easy_cleanup == NULL ||
        g_curl.easy_getinfo == NULL || g_curl.slist_append == NULL ||
        g_curl.slist_free_all == NULL || g_curl.easy_reset == NULL ||
        global_init == NULL) {
        dlclose(h);
        memset(&g_curl, 0, sizeof(g_curl));
        return;
    }

    /* libcurl's global init is not thread-safe (it may lazily bring up the
     * TLS backend); run it exactly once before any easy handle exists.
     * CURL_GLOBAL_DEFAULT == CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32 == 3. */
    if (global_init(3L) != 0) {
        dlclose(h);
        memset(&g_curl, 0, sizeof(g_curl));
        return;
    }
    g_curl.handle = h; /* publish last */
}

/* Thread-safe: concurrent first users synchronize on pthread_once instead
 * of racing a bare global (duplicate dlopen / torn function pointers). */
static int curl_load(void)
{
    pthread_once(&g_curl_once, curl_load_once);
    return g_curl.handle != NULL ? 0 : -1;
}

typedef struct {
    hlm_http_response *resp;
    int overflow;
} write_ctx;

static size_t curl_on_body(char *data, size_t size, size_t nmemb, void *user)
{
    write_ctx *w = (write_ctx *)user;
    size_t n = size * nmemb;

    if (w->resp->body_len + n > w->resp->body_cap) {
        w->overflow = 1;
        return 0; /* abort the transfer */
    }
    memcpy(w->resp->body + w->resp->body_len, data, n);
    w->resp->body_len += n;
    return n;
}

static size_t curl_on_header(char *data, size_t size, size_t nmemb, void *user)
{
    hlm_http_response *resp = (hlm_http_response *)user;
    size_t n = size * nmemb;

    /* delta-seconds Retry-After only (date form is ignored, like WinHTTP) */
    if (n > 12 && strncasecmp(data, "Retry-After:", 12) == 0) {
        /* curl header data is NOT NUL-terminated: copy the value into a
         * terminated local before strtol */
        char num[16];
        size_t m = n - 12;
        long v;
        if (m >= sizeof(num)) m = sizeof(num) - 1;
        memcpy(num, data + 12, m);
        num[m] = '\0';
        v = strtol(num, NULL, 10);
        if (v >= 0 && v < 24 * 3600) resp->retry_after_seconds = (int)v;
    }
    return n;
}

static int curl_send(void *user, const hlm_http_request *req,
                     hlm_http_response *resp)
{
    hlm_http_cache *cache = (hlm_http_cache *)user;
    hlm_CURL *curl;
    hlm_curl_slist *headers = NULL;
    char line[600];
    write_ctx w;
    long status = 0;
    int rc;

    resp->retry_after_seconds = -1;
    resp->body_len = 0;

    if (curl_load() != 0) return HLM_E_HTTP;

    /* With a cache, reuse one easy handle so the repeated same-host
     * requests of a refresh share a TCP/TLS connection; reset wipes every
     * option from the previous request. */
    if (cache != NULL && cache->h != NULL) {
        curl = (hlm_CURL *)cache->h;
        g_curl.easy_reset(curl);
    } else {
        curl = g_curl.easy_init();
        if (curl == NULL) return HLM_E_HTTP;
        if (cache != NULL) cache->h = curl;
    }

    w.resp = resp;
    w.overflow = 0;

    g_curl.easy_setopt(curl, HLM_CURLOPT_URL, req->url);
    g_curl.easy_setopt(curl, HLM_CURLOPT_NOSIGNAL, 1L);
    g_curl.easy_setopt(curl, HLM_CURLOPT_TIMEOUT_MS, (long)HLM_HTTP_TIMEOUT_MS);
    g_curl.easy_setopt(curl, HLM_CURLOPT_CONNECTTIMEOUT_MS,
                       (long)HLM_HTTP_TIMEOUT_MS);
    g_curl.easy_setopt(curl, HLM_CURLOPT_USERAGENT,
                       "license-management-core/1.0");
    g_curl.easy_setopt(curl, HLM_CURLOPT_WRITEFUNCTION, curl_on_body);
    g_curl.easy_setopt(curl, HLM_CURLOPT_WRITEDATA, &w);
    g_curl.easy_setopt(curl, HLM_CURLOPT_HEADERFUNCTION, curl_on_header);
    g_curl.easy_setopt(curl, HLM_CURLOPT_HEADERDATA, resp);

    if (strcmp(req->method, "GET") != 0)
        g_curl.easy_setopt(curl, HLM_CURLOPT_CUSTOMREQUEST, req->method);

    if (req->body != NULL) {
        g_curl.easy_setopt(curl, HLM_CURLOPT_POSTFIELDS, req->body);
        g_curl.easy_setopt(curl, HLM_CURLOPT_POSTFIELDSIZE,
                           (long)strlen(req->body));
        headers = g_curl.slist_append(headers, "Content-Type: application/json");
        /* curl adds Expect: 100-continue for larger bodies; suppress it */
        headers = g_curl.slist_append(headers, "Expect:");
    }
    if (req->api_key != NULL) {
        snprintf(line, sizeof(line), "X-API-KEY: %s", req->api_key);
        headers = g_curl.slist_append(headers, line);
    }
    if (req->correlation_id != NULL) {
        snprintf(line, sizeof(line), "X-Correlation-Id: %s",
                 req->correlation_id);
        headers = g_curl.slist_append(headers, line);
    }
    if (req->idempotency_key != NULL) {
        snprintf(line, sizeof(line), "Idempotency-Key: %s",
                 req->idempotency_key);
        headers = g_curl.slist_append(headers, line);
    }
    if (headers != NULL)
        g_curl.easy_setopt(curl, HLM_CURLOPT_HTTPHEADER, headers);

    rc = g_curl.easy_perform(curl);

    if (rc == 0)
        g_curl.easy_getinfo(curl, HLM_CURLINFO_RESPONSE_CODE, &status);

    if (headers != NULL) g_curl.slist_free_all(headers);
    if (cache == NULL) g_curl.easy_cleanup(curl);

    if (w.overflow) return HLM_E_BUFFER;
    if (rc != 0 || status == 0) return HLM_E_HTTP;

    resp->status = (int)status;
    return HLM_OK;
}

hlm_http hlm_http_curl(void)
{
    hlm_http h;
    h.send = curl_send;
    h.user = 0;
    return h;
}

hlm_http hlm_http_curl_cached(hlm_http_cache *cache)
{
    hlm_http h;
    h.send = curl_send;
    h.user = cache;
    return h;
}

void hlm_http_cache_close(hlm_http_cache *cache)
{
    if (cache == NULL || cache->h == NULL) return;
    g_curl.easy_cleanup((hlm_CURL *)cache->h); /* handle exists => loaded */
    cache->h = NULL;
}

/* ------------------------------------------------------------------ */
/* Sleep                                                               */
/* ------------------------------------------------------------------ */

static void sleep_posix(void *user, unsigned ms)
{
    struct timespec ts, rem;
    (void)user;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    /* retry on EINTR: host runtimes (Go preemption, JVM) signal freely and
     * would otherwise truncate the retry/backoff wait */
    while (nanosleep(&ts, &rem) == -1 && errno == EINTR)
        ts = rem;
}

hlm_sleep hlm_sleep_posix(void)
{
    hlm_sleep s;
    s.sleep_ms = sleep_posix;
    s.user = 0;
    return s;
}

/* ------------------------------------------------------------------ */
/* Trusted time (clock-tamper resistance)                              */
/* ------------------------------------------------------------------ */

/* Minimal SNTP client (RFC 4330), same packet handling as the Windows port. */
static int sntp_query(const char *host, int timeout_ms, int64_t *epoch_out)
{
    struct addrinfo hints, *ai = NULL;
    int sock = -1;
    uint8_t pkt[HLM_SNTP_PACKET_SIZE];
    int result = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, "123", &hints, &ai) != 0 || ai == NULL) return -1;

    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) goto done;

    {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    hlm_sntp_build_request(pkt);

    if (sendto(sock, pkt, sizeof(pkt), 0, ai->ai_addr, ai->ai_addrlen) !=
        (ssize_t)sizeof(pkt))
        goto done;
    if (recv(sock, pkt, sizeof(pkt), 0) != (ssize_t)sizeof(pkt)) goto done;

    if (hlm_sntp_parse_reply(pkt, epoch_out) != 0) goto done;
    result = 0;

done:
    if (sock >= 0) close(sock);
    if (ai != NULL) freeaddrinfo(ai);
    return result;
}

static int timesync_posix_now(void *user, int64_t *now_utc)
{
    char host[256] = "pool.ntp.org";
    int64_t ntp_time;

    (void)user;

#if defined(HLM_DEV_TIMESYNC_ENV)
    /* Dev/test hooks, compiled out of release builds: honoring these in
     * production would let an end user point trusted time at their own
     * (unauthenticated UDP) SNTP server, or disable it outright, and
     * resurrect expired licenses. */
    {
        const char *mode = getenv("HLM_TIMESYNC");
        const char *h = getenv("HLM_NTP_HOST");
        if (mode != NULL && strcmp(mode, "off") == 0)
            return HLM_E_HTTP; /* caller falls back to GET DateTime, then local */
        if (h != NULL && h[0] != '\0') {
            /* copy immediately: getenv's pointer can dangle if the host
             * app calls setenv/putenv on another thread */
            strncpy(host, h, sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
        }
    }
#endif

    if (sntp_query(host, HLM_NTP_TIMEOUT_MS, &ntp_time) == 0) {
        int64_t local = (int64_t)time(NULL);
        int64_t drift = local - ntp_time;
        if (drift < 0) drift = -drift;
        *now_utc = drift < HLM_MAX_DRIFT_SECONDS ? local : ntp_time;
        return HLM_OK;
    }

    return HLM_E_HTTP;
}

hlm_timesync hlm_timesync_posix(void)
{
    hlm_timesync t;
    t.now = timesync_posix_now;
    t.user = 0;
    return t;
}

/* ------------------------------------------------------------------ */
/* Machine identity                                                    */
/* ------------------------------------------------------------------ */

#if defined(__APPLE__)
#include <sys/types.h>
#include <uuid/uuid.h>

static int os_machine_id(char *out, size_t out_len)
{
    uuid_t uu;
    struct timespec timeout = { 3, 0 };
    char s[37];

    if (gethostuuid(uu, &timeout) != 0) return -1;
    uuid_unparse_lower(uu, s);
    if (strlen(s) >= out_len) return -1;
    strcpy(out, s);
    return 0;
}
#else
/* Linux: the systemd/dbus machine id — stable across reboots, set once at
 * install/first boot. */
static int os_machine_id(char *out, size_t out_len)
{
    static const char *const PATHS[] = {
        "/etc/machine-id", "/var/lib/dbus/machine-id"
    };
    size_t i;

    for (i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
        FILE *f = fopen(PATHS[i], "rb");
        size_t n;
        if (f == NULL) continue;
        n = fread(out, 1, out_len - 1, f);
        fclose(f);
        while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                         out[n - 1] == ' '))
            n--;
        out[n] = '\0';
        if (n >= 8) return 0; /* sane id */
    }
    return -1;
}
#endif

int hlm_machine_id_posix(char *out, size_t out_len)
{
    char id[128];
    const char *components[1];

    if (os_machine_id(id, sizeof(id)) != 0)
        return HLM_E_ARG; /* no OS machine id — caller must supply one */

    components[0] = id;
    return hlm_fingerprint(components, 1, out, out_len);
}

int hlm_machine_name_posix(char *out, size_t out_len)
{
    if (out == NULL || out_len == 0) return HLM_E_ARG;
    if (gethostname(out, out_len) != 0) return HLM_E_ARG;
    out[out_len - 1] = '\0';
    return HLM_OK;
}

#endif /* !_WIN32 */
