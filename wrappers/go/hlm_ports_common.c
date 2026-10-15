/* Portable default ports: stdio file storage and time(NULL) clock.
 * Embedded targets replace these with flash/RTC-backed implementations. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "hymma/hlm.h"
#include "hlm_sntp.h"

/* ---- SNTP packet helpers shared by the platform ports ---- */

void hlm_sntp_build_request(uint8_t pkt[HLM_SNTP_PACKET_SIZE])
{
    memset(pkt, 0, HLM_SNTP_PACKET_SIZE);
    pkt[0] = 0x1B; /* LI=0, VN=3, Mode=3 (client) */
}

int hlm_sntp_parse_reply(const uint8_t pkt[HLM_SNTP_PACKET_SIZE],
                         int64_t *epoch_out)
{
    /* transmit timestamp: seconds since 1900-01-01, bytes 40-43 big-endian */
    uint32_t secs = ((uint32_t)pkt[40] << 24) | ((uint32_t)pkt[41] << 16) |
                    ((uint32_t)pkt[42] << 8) | (uint32_t)pkt[43];
    if (secs == 0) return -1;
    /* NTP era pivot: era-0 timestamps have the top bit set from 1968 through
     * Feb-2036; a clear top bit means era 1 — add 2^32 s so trusted time
     * keeps working past the rollover. 2208988800 s separate 1900 and 1970. */
    *epoch_out = (int64_t)secs +
                 ((secs & 0x80000000u) ? 0 : 4294967296LL) - 2208988800LL;
    return 0;
}

/* ---- transport error -> hlm_net_failure ------------------------------
 * Numeric codes spelled out (with their names) instead of winhttp.h /
 * curl.h macros so these mappings compile — and are tested — on every
 * platform, and custom ports over either stack can reuse them. */

hlm_net_failure hlm_net_failure_from_winhttp(unsigned long error)
{
    switch (error) {
    case 12007: /* ERROR_WINHTTP_NAME_NOT_RESOLVED */
    case 11001: /* WSAHOST_NOT_FOUND */
    case 11002: /* WSATRY_AGAIN */
    case 11004: /* WSANO_DATA: "name is valid, but no data of the requested type" */
        return HLM_NET_NAME_RESOLUTION;

    case 12037: /* ERROR_WINHTTP_SECURE_CERT_DATE_INVALID */
    case 12038: /* ERROR_WINHTTP_SECURE_CERT_CN_INVALID */
    case 12044: /* ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED */
    case 12045: /* ERROR_WINHTTP_SECURE_INVALID_CA */
    case 12057: /* ERROR_WINHTTP_SECURE_CERT_REV_FAILED */
    case 12157: /* ERROR_WINHTTP_SECURE_CHANNEL_ERROR */
    case 12169: /* ERROR_WINHTTP_SECURE_INVALID_CERT */
    case 12170: /* ERROR_WINHTTP_SECURE_CERT_REVOKED */
    case 12175: /* ERROR_WINHTTP_SECURE_FAILURE */
    case 12179: /* ERROR_WINHTTP_SECURE_CERT_WRONG_USAGE */
    case 12185: /* ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY */
    case 12186: /* ERROR_WINHTTP_CLIENT_CERT_NO_ACCESS_PRIVATE_KEY */
        return HLM_NET_SECURE_CONNECTION;

    case 12166: /* ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT */
    case 12167: /* ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT */
    case 12178: /* ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR */
    case 12180: /* ERROR_WINHTTP_AUTODETECTION_FAILED */
        return HLM_NET_PROXY;

    case 12002: /* ERROR_WINHTTP_TIMEOUT */
    case 10060: /* WSAETIMEDOUT */
        return HLM_NET_TIMEOUT;

    case 12029: /* ERROR_WINHTTP_CANNOT_CONNECT */
    case 12030: /* ERROR_WINHTTP_CONNECTION_ERROR */
    case 12152: /* ERROR_WINHTTP_INVALID_SERVER_RESPONSE */
    case 10054: /* WSAECONNRESET */
    case 10061: /* WSAECONNREFUSED */
        return HLM_NET_CONNECTION;

    default:
        return HLM_NET_UNKNOWN;
    }
}

hlm_net_failure hlm_net_failure_from_curl(int curl_code)
{
    switch (curl_code) {
    case 6:  /* CURLE_COULDNT_RESOLVE_HOST */
        return HLM_NET_NAME_RESOLUTION;

    case 35: /* CURLE_SSL_CONNECT_ERROR */
    case 51: /* CURLE_PEER_FAILED_VERIFICATION (pre-7.62 number) */
    case 53: /* CURLE_SSL_ENGINE_NOTFOUND */
    case 54: /* CURLE_SSL_ENGINE_SETFAILED */
    case 58: /* CURLE_SSL_CERTPROBLEM */
    case 59: /* CURLE_SSL_CIPHER */
    case 60: /* CURLE_PEER_FAILED_VERIFICATION */
    case 77: /* CURLE_SSL_CACERT_BADFILE */
    case 80: /* CURLE_SSL_SHUTDOWN_FAILED */
    case 82: /* CURLE_SSL_CRL_BADFILE */
    case 83: /* CURLE_SSL_ISSUER_ERROR */
    case 90: /* CURLE_SSL_PINNEDPUBKEYNOTMATCH */
    case 91: /* CURLE_SSL_INVALIDCERTSTATUS */
        return HLM_NET_SECURE_CONNECTION;

    case 5:  /* CURLE_COULDNT_RESOLVE_PROXY */
    case 97: /* CURLE_PROXY */
        return HLM_NET_PROXY;

    case 28: /* CURLE_OPERATION_TIMEDOUT */
        return HLM_NET_TIMEOUT;

    case 7:  /* CURLE_COULDNT_CONNECT */
    case 52: /* CURLE_GOT_NOTHING */
    case 55: /* CURLE_SEND_ERROR */
    case 56: /* CURLE_RECV_ERROR */
        return HLM_NET_CONNECTION;

    default:
        return HLM_NET_UNKNOWN;
    }
}

static int64_t clock_now(void *user)
{
    (void)user;
    return (int64_t)time(NULL);
}

hlm_clock hlm_clock_system(void)
{
    hlm_clock c;
    c.now = clock_now;
    c.user = 0;
    return c;
}

static int file_read(void *user, char *buf, size_t cap)
{
    hlm_storage_file_cfg *cfg = (hlm_storage_file_cfg *)user;
    FILE *f;
    size_t n;

    f = fopen(cfg->path, "rb");
    if (f == NULL) return 0; /* absent */
    n = fread(buf, 1, cap, f);
    if (ferror(f)) {
        fclose(f);
        return HLM_E_STORAGE;
    }
    if (!feof(f) && n == cap) {
        fclose(f);
        return HLM_E_BUFFER; /* file larger than buffer */
    }
    fclose(f);
    return (int)n;
}

static int file_write(void *user, const char *data, size_t len)
{
    hlm_storage_file_cfg *cfg = (hlm_storage_file_cfg *)user;
    char tmp[576];
    FILE *f;
    size_t n;

    /* Write to a temp file, then rename over the target: a reader sharing
     * the path never observes a half-written cache, and a crash mid-write
     * cannot truncate an existing license. */
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", cfg->path) >= (int)sizeof(tmp))
        return HLM_E_STORAGE;

    f = fopen(tmp, "wb");
    if (f == NULL) return HLM_E_STORAGE;
    n = fwrite(data, 1, len, f);
    if (fclose(f) != 0 || n != len) {
        remove(tmp);
        return HLM_E_STORAGE;
    }

#if defined(_WIN32)
    if (!MoveFileExA(tmp, cfg->path, MOVEFILE_REPLACE_EXISTING)) {
        remove(tmp);
        return HLM_E_STORAGE;
    }
#else
    if (rename(tmp, cfg->path) != 0) {
        remove(tmp);
        return HLM_E_STORAGE;
    }
#endif
    return HLM_OK;
}

hlm_storage hlm_storage_file(hlm_storage_file_cfg *cfg)
{
    hlm_storage s;
    s.read = file_read;
    s.write = file_write;
    s.user = cfg;
    return s;
}
