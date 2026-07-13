/* license-management-core — portable license-management client core.
 *
 * One C library that is the source of truth for verifying and managing
 * Hymma License-Management licenses on every platform: Windows/macOS/Linux
 * desktops, servers, and bare-metal / RTOS IoT devices. Higher-level SDKs
 * (.NET, Python, Java, Node, Go, ...) are thin FFI wrappers over this ABI —
 * the same architecture Cryptlex LexActivator, Wibu CodeMeter and Thales
 * Sentinel use.
 *
 * Design rules:
 *  - C99, no dynamic allocation anywhere in the library.
 *  - No OS calls in the core; everything platform-specific enters through
 *    small "ports" (HTTP, storage, clock, device identity, crypto) that the
 *    host can replace. Built-in Windows ports are provided; an MCU provides
 *    its own or runs fully offline.
 *  - Licenses are compact JWS strings (`GET /api/license?format=jws|es256|eddsa`),
 *    verified against the vendor's public key — never XML-DSig.
 */
#ifndef HYMMA_LM_H
#define HYMMA_LM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

typedef enum {
    HLM_OK = 0,
    HLM_E_ARG = -1,            /* invalid argument */
    HLM_E_BUFFER = -2,         /* caller buffer too small */
    HLM_E_FORMAT = -3,         /* malformed JWS / JSON / key */
    HLM_E_SIGNATURE = -4,      /* signature did not verify — treat as tampered */
    HLM_E_UNSUPPORTED_ALG = -5,/* algorithm not compiled in / unknown */
    HLM_E_NO_LICENSE = -6,     /* no cached license and no way to fetch one */
    HLM_E_HTTP = -7,           /* transport error (no connectivity etc.) */
    HLM_E_API = -8,            /* server answered with a non-success status */
    HLM_E_STORAGE = -9,        /* storage port read/write failure */
    HLM_E_PRODUCT_MISMATCH = -10, /* license is for a different product */
    HLM_E_COMPUTER_MISMATCH = -11,/* license is for a different machine */
    HLM_E_AUTH = -12,          /* 401/403 — bad API key */
    HLM_E_TRIAL_QUOTA = -13,   /* vendor's active-trial quota exhausted (402 trial_quota) */
    HLM_E_PAID_FORMAT_REQUIRED = -14, /* product policy: this format needs a paid receipt */
    HLM_E_PLAN_LIMIT = -15     /* vendor plan cap reached (ALU / sandbox limits) */
} hlm_err;

const char *hlm_err_str(int err);

/* ------------------------------------------------------------------ */
/* Keys & crypto port                                                  */
/* ------------------------------------------------------------------ */

typedef enum {
    HLM_ALG_RS256 = 1, /* RSASSA-PKCS1-v1_5 + SHA-256 (vendor RSA key)   */
    HLM_ALG_ES256 = 2, /* ECDSA P-256 + SHA-256, r||s (vendor EC key)    */
    HLM_ALG_EDDSA = 3  /* Ed25519 (vendor Ed25519 key)                   */
} hlm_alg;

/* A vendor public key. Raw big-endian components — exactly what a JWK
 * carries after base64url-decoding, so keys can be pasted at build time
 * or parsed at runtime with hlm_jwk_parse(). */
typedef struct {
    hlm_alg alg;
    union {
        struct {
            const uint8_t *n; size_t n_len;  /* modulus  */
            const uint8_t *e; size_t e_len;  /* exponent */
        } rsa;
        struct {
            const uint8_t *x; /* 32 bytes */
            const uint8_t *y; /* 32 bytes */
        } ec;
        struct {
            const uint8_t *pub; /* 32 bytes */
        } ed25519;
    } u;
} hlm_public_key;

/* Crypto port: verify `sig` over `msg` with `key`.
 * Return 1 valid, 0 invalid, <0 hlm_err. */
typedef struct {
    int (*verify)(void *user, const hlm_public_key *key,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);
    void *user;
} hlm_crypto;

/* Built-in pure-C backend (RS256 + ES256 + EdDSA/Ed25519). */
hlm_crypto hlm_crypto_portable(void);

#if defined(_WIN32)
/* Windows CNG (bcrypt) backend — RS256 + ES256 via the OS; EdDSA via the
 * portable Ed25519 verifier (CNG has no Ed25519). */
hlm_crypto hlm_crypto_cng(void);
#endif

/* Parse one JWK JSON object ({"kty":"RSA","n":...,"e":...} or
 * {"kty":"EC","crv":"P-256","x":...,"y":...} or {"kty":"OKP","crv":"Ed25519",...})
 * into `key`, decoding components into `keybuf`. */
int hlm_jwk_parse(const char *jwk_json, size_t len,
                  hlm_public_key *key, uint8_t *keybuf, size_t keybuf_len);

/* ------------------------------------------------------------------ */
/* License model                                                       */
/* ------------------------------------------------------------------ */

#ifndef HLM_MAX_ID
#define HLM_MAX_ID 64          /* LIC_/PRD_/PC_/VDR_ ULIDs are 30 chars */
#endif
#ifndef HLM_MAX_NAME
#define HLM_MAX_NAME 128
#endif
#ifndef HLM_MAX_MACHINE_ID
#define HLM_MAX_MACHINE_ID 64  /* fingerprint is 52 chars */
#endif
#ifndef HLM_MAX_EMAIL
#define HLM_MAX_EMAIL 128
#endif
#ifndef HLM_MAX_CODE
#define HLM_MAX_CODE 128
#endif
#ifndef HLM_MAX_ERROR_DETAIL
#define HLM_MAX_ERROR_DETAIL 256
#endif
#ifndef HLM_MAX_METADATA
#define HLM_MAX_METADATA 8
#endif
#ifndef HLM_MAX_META_KEY
#define HLM_MAX_META_KEY 64
#endif
#ifndef HLM_MAX_META_VALUE
#define HLM_MAX_META_VALUE 128
#endif

/* Mirrors LicenseStatusTitles in the .NET SDK. */
typedef enum {
    HLM_STATUS_UNKNOWN = 0,
    HLM_STATUS_EXPIRED,             /* license FILE lapsed — refresh from server */
    HLM_STATUS_VALID,               /* paid & active */
    HLM_STATUS_VALID_TRIAL,
    HLM_STATUS_INVALID_TRIAL,       /* trial period over */
    HLM_STATUS_RECEIPT_EXPIRED,     /* subscription ended */
    HLM_STATUS_RECEIPT_UNREGISTERED /* seat freed (uninstalled elsewhere) */
} hlm_status;

const char *hlm_status_str(hlm_status s);

typedef struct {
    char key[HLM_MAX_META_KEY];
    char value[HLM_MAX_META_VALUE];
} hlm_metadata;

typedef struct {
    char id[HLM_MAX_ID];
    char code[HLM_MAX_CODE];        /* redacted ("") in signed files */
    int qty;
    char buyer_email[HLM_MAX_EMAIL];
    int64_t expires;                /* unix seconds; HLM_TIME_NONE if null */
} hlm_receipt;

typedef struct {
    char id[HLM_MAX_ID];
    char name[HLM_MAX_NAME];
    char vendor_id[HLM_MAX_ID];
    char vendor_name[HLM_MAX_NAME];
} hlm_product;

typedef struct {
    char id[HLM_MAX_ID];
    char machine_id[HLM_MAX_MACHINE_ID]; /* "MacAddress" on the wire */
    char name[HLM_MAX_NAME];
} hlm_computer;

#define HLM_TIME_NONE INT64_MIN

typedef struct {
    char id[HLM_MAX_ID];
    hlm_status server_status;   /* Status claim as signed by the server */
    int live_mode;              /* 0 = sandbox-signed license */
    int64_t trial_end;          /* unix seconds */
    int64_t first_paid_on;      /* HLM_TIME_NONE if never paid */
    int64_t expires;            /* license FILE expiry */
    int64_t created;            /* HLM_TIME_NONE if absent */
    int64_t updated;            /* HLM_TIME_NONE = never activated (trial) */
    int has_receipt;
    hlm_receipt receipt;
    hlm_product product;
    hlm_computer computer;
    int metadata_count;
    hlm_metadata metadata[HLM_MAX_METADATA];
} hlm_license;

/* ------------------------------------------------------------------ */
/* Low-level verification (this is ALL an offline IoT device needs)    */
/* ------------------------------------------------------------------ */

/* Verify a compact JWS against `keys` (first key whose alg matches the JWS
 * header is tried, then the rest). On success points *payload_out at the
 * decoded payload JSON inside `workbuf`.
 * Returns HLM_OK or an hlm_err. */
int hlm_jws_verify(const char *jws, size_t jws_len,
                   const hlm_public_key *keys, size_t key_count,
                   const hlm_crypto *crypto,
                   uint8_t *workbuf, size_t workbuf_len,
                   const char **payload_out, size_t *payload_len_out);

/* Parse a verified license payload JSON into `lic`. */
int hlm_license_parse(const char *payload_json, size_t len, hlm_license *lic);

/* Evaluate effective status at `now` (unix seconds), mirroring the .NET
 * SDK's LicenseStatus rules: file expiry always wins; otherwise the signed
 * server status; otherwise the legacy trial/receipt fallback. */
hlm_status hlm_license_status(const hlm_license *lic, int64_t now);

/* One call: verify + parse + evaluate.
 * `expected_product_id` / `expected_machine_id` may be NULL to skip binding
 * checks (a device that IS the fingerprint source should pass its own id). */
int hlm_license_check(const char *jws, size_t jws_len,
                      const hlm_public_key *keys, size_t key_count,
                      const hlm_crypto *crypto,
                      const char *expected_product_id,
                      const char *expected_machine_id,
                      int64_t now,
                      hlm_license *lic, hlm_status *status_out);

/* ------------------------------------------------------------------ */
/* Device identity helper                                              */
/* ------------------------------------------------------------------ */

/* Portable fingerprint: SHA-256("{component1},{component2},...") encoded as
 * 52-char Crockford Base32 — byte-identical to the .NET SDK's DeviceId
 * pipeline when fed (motherboard serial, processor id) in that order.
 * An MCU passes its factory UID as the single component.
 * `out` must hold >= 53 bytes. */
int hlm_fingerprint(const char *const *components, size_t count,
                    char *out, size_t out_len);

#if defined(_WIN32)
/* Windows: motherboard serial (SMBIOS type 2) + ProcessorId (CPUID), matching
 * WMI Win32_BaseBoard.SerialNumber / Win32_Processor.ProcessorId, then
 * hlm_fingerprint(). Produces the same MachineId as the .NET SDK. */
int hlm_machine_id_win(char *out, size_t out_len);
/* Computer name as the SDK sends it (Environment.MachineName equivalent). */
int hlm_machine_name_win(char *out, size_t out_len);
#else
/* POSIX: the stable OS machine id (/etc/machine-id on Linux, gethostuuid()
 * on macOS) through hlm_fingerprint() — the id itself never leaves the box. */
int hlm_machine_id_posix(char *out, size_t out_len);
/* gethostname() */
int hlm_machine_name_posix(char *out, size_t out_len);
#endif

/* ------------------------------------------------------------------ */
/* Ports                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *method;        /* "GET" | "POST" | "PATCH" */
    const char *url;           /* absolute */
    const char *body;          /* JSON or NULL */
    const char *api_key;       /* X-API-KEY */
    const char *idempotency_key; /* or NULL */
    const char *correlation_id;  /* or NULL */
} hlm_http_request;

typedef struct {
    int status;                /* HTTP status, 0 on transport failure */
    char *body;                /* caller-provided buffer */
    size_t body_cap;
    size_t body_len;           /* filled by transport */
    int retry_after_seconds;   /* parsed Retry-After header; -1 if absent */
} hlm_http_response;

/* Return HLM_OK when a response (any status) was received. */
typedef struct {
    int (*send)(void *user, const hlm_http_request *req, hlm_http_response *resp);
    void *user;
} hlm_http;

#if defined(_WIN32)
hlm_http hlm_http_winhttp(void); /* built-in WinHTTP transport */
#else
/* libcurl transport; libcurl is dlopen()ed at first use so the library
 * itself has no link-time dependency. Fails with HLM_E_HTTP if no libcurl
 * is present on the system. */
hlm_http hlm_http_curl(void);
#endif

/* Optional per-client HTTP connection cache. The plain constructors above
 * tear the whole transport down after every request; binding a cache keeps
 * one transport handle alive (curl easy handle / WinHTTP session) so the
 * repeated same-host requests of a refresh share one TCP/TLS session.
 * Same thread-safety contract as the client that owns it; close only after
 * the owning client is done. Zero-initialize before first use. */
typedef struct { void *h; } hlm_http_cache;

#if defined(_WIN32)
hlm_http hlm_http_winhttp_cached(hlm_http_cache *cache);
#else
hlm_http hlm_http_curl_cached(hlm_http_cache *cache);
#endif

void hlm_http_cache_close(hlm_http_cache *cache);

/* Blob storage for the cached license (a file on desktops, flash on MCUs). */
typedef struct {
    /* Return bytes read, 0 if absent, <0 on failure. */
    int (*read)(void *user, char *buf, size_t cap);
    /* Return HLM_OK on success. */
    int (*write)(void *user, const char *data, size_t len);
    void *user;
} hlm_storage;

/* File-based storage. `path` must outlive the storage. */
typedef struct { const char *path; } hlm_storage_file_cfg;
hlm_storage hlm_storage_file(hlm_storage_file_cfg *cfg);

/* Unix-seconds clock; on MCUs wire this to the RTC. */
typedef struct {
    int64_t (*now)(void *user);
    void *user;
} hlm_clock;

hlm_clock hlm_clock_system(void); /* time(NULL) */

/* Backoff sleep between HTTP retries. Optional: without it, retries are
 * immediate (still bounded by the attempt count). */
typedef struct {
    void (*sleep_ms)(void *user, unsigned ms);
    void *user;
} hlm_sleep;

#if defined(_WIN32)
hlm_sleep hlm_sleep_win(void); /* Sleep() */
#else
hlm_sleep hlm_sleep_posix(void); /* nanosleep() */
#endif

/* Trusted-time source for clock-tamper resistance (the .NET SDK's
 * TimeSyncDiagnostic concept). Return HLM_OK and a trusted unix time, or an
 * error to make the client fall back to GET DateTime, then the local clock. */
typedef struct {
    int (*now)(void *user, int64_t *now_utc);
    void *user;
} hlm_timesync;

#if defined(_WIN32)
/* Windows cascade: local clock IF the w32time service is running, configured
 * for NTP, and within 1h of time.windows.com; otherwise SNTP pool.ntp.org. */
hlm_timesync hlm_timesync_win(void);
#else
/* POSIX cascade: SNTP to pool.ntp.org (HLM_NTP_HOST overrides the host,
 * HLM_TIMESYNC=off disables); local clock wins when within 1h of the NTP
 * answer, otherwise the NTP answer itself. */
hlm_timesync hlm_timesync_posix(void);
#endif

/* ------------------------------------------------------------------ */
/* High-level client (online flow — desktops/servers/connected IoT)    */
/* ------------------------------------------------------------------ */

#ifndef HLM_CLIENT_BUF
#define HLM_CLIENT_BUF 16384   /* holds one signed license + one response */
#endif

typedef struct {
    const char *base_url;      /* default: https://license-management.com/api/ */
    const char *vendor_id;     /* VDR_... (informational) */
    const char *product_id;    /* PRD_... */
    const char *client_api_key;/* PUB_... — NEVER a MST_ key */
    uint32_t valid_days;       /* license file validity to request; 0 => 90 */
    hlm_alg format;            /* which signed format to request */

    const hlm_public_key *keys;/* trusted vendor public keys */
    size_t key_count;

    const char *machine_id;    /* fingerprint (52 chars) */
    const char *machine_name;

    hlm_crypto crypto;
    hlm_http http;             /* send==NULL => offline-only */
    hlm_storage storage;       /* read==NULL => no cache */
    hlm_clock clock;
    hlm_sleep sleep;           /* optional: retry backoff waits */
    hlm_timesync timesync;     /* optional: clock-tamper resistance */
} hlm_client_cfg;

typedef struct {
    hlm_client_cfg cfg;
    hlm_license license;       /* last good license */
    hlm_status status;
    int has_license;
    int last_http_status;
    char last_error[HLM_MAX_ERROR_DETAIL]; /* server's refusal detail ("" if none) */
    int64_t eval_now;          /* trusted evaluation time of the last call */
    int64_t time_floor;        /* highest trusted time observed; the local-
                                  clock fallback never evaluates below it */
    uint32_t corr_counter;     /* per-handle correlation-id sequence */
    char buf[HLM_CLIENT_BUF];
    char resp[HLM_CLIENT_BUF];
} hlm_client;

int hlm_client_init(hlm_client *c, const hlm_client_cfg *cfg);

/* Silent check & trial bootstrap (the SDK's Launch+Install flow):
 * cached license if fresh; otherwise registers the computer, obtains a
 * (trial) license from the server, verifies, caches, evaluates. */
int hlm_client_check(hlm_client *c);

/* Attach a purchased receipt code to this machine's license, then refresh. */
int hlm_client_activate(hlm_client *c, const char *receipt_code);

/* Free this machine's seat (uninstall), then refresh the cached file. */
int hlm_client_deactivate(hlm_client *c);

/* Force a fresh signed license from the server (ignores cache). */
int hlm_client_refresh(hlm_client *c);

#ifdef __cplusplus
}
#endif

#endif /* HYMMA_LM_H */
