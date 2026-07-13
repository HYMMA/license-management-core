/* Windows ports: WinHTTP transport, machine identity, sleep, trusted time.
 *
 * Machine identity reproduces the .NET SDK's DeviceId pipeline without WMI:
 *   Win32_BaseBoard.SerialNumber   -> SMBIOS type 2 serial (GetSystemFirmwareTable)
 *   Win32_Processor.ProcessorId    -> CPUID leaf 1, "%08X%08X" of EDX,EAX
 * so the same physical machine registers as the SAME computer whether the
 * vendor ships the .NET SDK or this core.
 *
 * Trusted time reproduces the SDK's TimeSyncDiagnostic cascade:
 *   local clock IF w32time is running, configured for NTP, and within 1h of
 *   time.windows.com; otherwise SNTP to pool.ntp.org; otherwise fail (the
 *   client then falls back to GET DateTime, then the local clock).
 */
#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <intrin.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hymma/hlm.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#define HLM_HTTP_TIMEOUT_MS 15000 /* per request, matches the .NET SDK */
#define HLM_NTP_TIMEOUT_MS 3000
#define HLM_MAX_DRIFT_SECONDS 3600 /* 1.0 hour, matches TimeSyncConstants */

/* ------------------------------------------------------------------ */
/* WinHTTP transport                                                   */
/* ------------------------------------------------------------------ */

static int utf8_to_wide(const char *s, wchar_t *out, int cap)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, out, cap);
    return n > 0 ? 0 : -1;
}

static int winhttp_send(void *user, const hlm_http_request *req,
                        hlm_http_response *resp)
{
    HINTERNET session = NULL, connect = NULL, request = NULL;
    wchar_t wurl[1024], whost[256], wpath[768], wmethod[16];
    wchar_t headers[1024];
    URL_COMPONENTS uc;
    int result = HLM_E_HTTP;
    DWORD status = 0, status_len = sizeof(status);
    size_t total = 0;

    (void)user;
    resp->retry_after_seconds = -1;

    if (utf8_to_wide(req->url, wurl, 1024) < 0 ||
        utf8_to_wide(req->method, wmethod, 16) < 0)
        return HLM_E_ARG;

    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = whost;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = wpath;
    uc.dwUrlPathLength = 768;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return HLM_E_ARG;

    session = WinHttpOpen(L"license-management-core/1.0",
                          WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == NULL) goto done;

    WinHttpSetTimeouts(session, HLM_HTTP_TIMEOUT_MS, HLM_HTTP_TIMEOUT_MS,
                       HLM_HTTP_TIMEOUT_MS, HLM_HTTP_TIMEOUT_MS);

    connect = WinHttpConnect(session, whost, uc.nPort, 0);
    if (connect == NULL) goto done;

    request = WinHttpOpenRequest(
        connect, wmethod, wpath, NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (request == NULL) goto done;

    {
        wchar_t wkey[256], wcorr[64], widem[300];
        int hl = 0;
        headers[0] = L'\0';
        if (req->api_key != NULL && utf8_to_wide(req->api_key, wkey, 256) == 0)
            hl += _snwprintf(headers + hl, 1024 - hl, L"X-API-KEY: %s\r\n", wkey);
        if (req->correlation_id != NULL &&
            utf8_to_wide(req->correlation_id, wcorr, 64) == 0)
            hl += _snwprintf(headers + hl, 1024 - hl,
                             L"X-Correlation-Id: %s\r\n", wcorr);
        if (req->idempotency_key != NULL &&
            utf8_to_wide(req->idempotency_key, widem, 300) == 0)
            hl += _snwprintf(headers + hl, 1024 - hl,
                             L"Idempotency-Key: %s\r\n", widem);
        if (req->body != NULL)
            hl += _snwprintf(headers + hl, 1024 - hl,
                             L"Content-Type: application/json\r\n");
        (void)hl;
    }

    if (!WinHttpSendRequest(request,
                            headers[0] != L'\0' ? headers : WINHTTP_NO_ADDITIONAL_HEADERS,
                            (DWORD)-1,
                            req->body != NULL ? (LPVOID)req->body : WINHTTP_NO_REQUEST_DATA,
                            req->body != NULL ? (DWORD)strlen(req->body) : 0,
                            req->body != NULL ? (DWORD)strlen(req->body) : 0,
                            0))
        goto done;

    if (!WinHttpReceiveResponse(request, NULL)) goto done;

    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len,
                             WINHTTP_NO_HEADER_INDEX))
        goto done;

    /* Retry-After (delta-seconds form; date form is ignored) */
    {
        wchar_t ra[64];
        DWORD ra_len = sizeof(ra);
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_RETRY_AFTER,
                                WINHTTP_HEADER_NAME_BY_INDEX, ra, &ra_len,
                                WINHTTP_NO_HEADER_INDEX)) {
            long v = wcstol(ra, NULL, 10);
            if (v >= 0 && v < 24 * 3600) resp->retry_after_seconds = (int)v;
        }
    }

    for (;;) {
        DWORD avail = 0, got = 0;
        if (!WinHttpQueryDataAvailable(request, &avail)) goto done;
        if (avail == 0) break;
        if (total + avail > resp->body_cap) {
            result = HLM_E_BUFFER;
            goto done;
        }
        if (!WinHttpReadData(request, resp->body + total, avail, &got)) goto done;
        total += got;
    }

    resp->status = (int)status;
    resp->body_len = total;
    result = HLM_OK;

done:
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
    return result;
}

hlm_http hlm_http_winhttp(void)
{
    hlm_http h;
    h.send = winhttp_send;
    h.user = 0;
    return h;
}

/* ------------------------------------------------------------------ */
/* Sleep                                                               */
/* ------------------------------------------------------------------ */

static void sleep_win(void *user, unsigned ms)
{
    (void)user;
    Sleep(ms);
}

hlm_sleep hlm_sleep_win(void)
{
    hlm_sleep s;
    s.sleep_ms = sleep_win;
    s.user = 0;
    return s;
}

/* ------------------------------------------------------------------ */
/* Trusted time (clock-tamper resistance)                              */
/* ------------------------------------------------------------------ */

/* One process-wide WSAStartup at first use: per-query startup/cleanup
 * churns the global Winsock refcount and is fragile next to a host app
 * managing Winsock itself. The matching WSACleanup is intentionally
 * omitted — the OS reclaims it at process exit. */
static INIT_ONCE g_wsa_once = INIT_ONCE_STATIC_INIT;
static int g_wsa_ok = 0;

static BOOL CALLBACK wsa_init_once(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    WSADATA wsa;
    (void)once; (void)param; (void)ctx;
    g_wsa_ok = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    return TRUE;
}

/* Minimal SNTP client (RFC 4330): 48-byte packet, LI=0 VN=3 Mode=3,
 * transmit timestamp at bytes 40-47, epoch 1900-01-01. */
static int sntp_query(const char *host, int timeout_ms, int64_t *epoch_out)
{
    struct addrinfo hints, *ai = NULL;
    SOCKET sock = INVALID_SOCKET;
    uint8_t pkt[48];
    int result = -1;

    InitOnceExecuteOnce(&g_wsa_once, wsa_init_once, NULL, NULL);
    if (!g_wsa_ok) return -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (getaddrinfo(host, "123", &hints, &ai) != 0 || ai == NULL) goto done;

    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock == INVALID_SOCKET) goto done;

    {
        DWORD tmo = (DWORD)timeout_ms;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof(tmo));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tmo, sizeof(tmo));
    }

    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x1B; /* LI=0, VN=3, Mode=3 (client) — same as NtpConnection */

    if (sendto(sock, (const char *)pkt, sizeof(pkt), 0, ai->ai_addr,
               (int)ai->ai_addrlen) != sizeof(pkt))
        goto done;
    if (recv(sock, (char *)pkt, sizeof(pkt), 0) != sizeof(pkt)) goto done;

    {
        /* seconds since 1900-01-01 from bytes 40-43 (big-endian) */
        uint32_t secs = ((uint32_t)pkt[40] << 24) | ((uint32_t)pkt[41] << 16) |
                        ((uint32_t)pkt[42] << 8) | (uint32_t)pkt[43];
        if (secs == 0) goto done;
        /* 2208988800 = seconds between 1900-01-01 and 1970-01-01.
         * NTP era pivot: era-0 timestamps have the top bit set from 1968
         * through Feb-2036; a clear top bit means era 1 — add 2^32 s so
         * trusted time keeps working past the rollover. */
        *epoch_out = (int64_t)secs +
                     ((secs & 0x80000000u) ? 0 : 4294967296LL) - 2208988800LL;
        result = 0;
    }

done:
    if (sock != INVALID_SOCKET) closesocket(sock);
    if (ai != NULL) freeaddrinfo(ai);
    return result;
}

static int w32time_running(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS ss;
    int running = 0;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) return 0;
    svc = OpenServiceA(scm, "w32time", SERVICE_QUERY_STATUS);
    if (svc != NULL) {
        if (QueryServiceStatus(svc, &ss))
            running = ss.dwCurrentState == SERVICE_RUNNING;
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

static int w32time_uses_ntp(void)
{
    char type[32];
    DWORD len = sizeof(type);
    if (RegGetValueA(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters",
                     "Type", RRF_RT_REG_SZ, NULL, type, &len) != ERROR_SUCCESS)
        return 0;
    return _stricmp(type, "NTP") == 0;
}

static int64_t local_utc_now(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    /* FILETIME epoch 1601-01-01, 100ns ticks */
    return (int64_t)(u.QuadPart / 10000000ULL) - 11644473600LL;
}

static int timesync_win_now(void *user, int64_t *now_utc)
{
    int64_t ntp_time;

    (void)user;

    /* Trust the local clock only when Windows itself keeps it honest AND it
     * actually agrees with an authoritative source — same three checks as
     * the SDK's TimeSyncDiagnostic. */
    if (w32time_running() && w32time_uses_ntp() &&
        sntp_query("time.windows.com", HLM_NTP_TIMEOUT_MS, &ntp_time) == 0) {
        int64_t local = local_utc_now();
        int64_t drift = local - ntp_time;
        if (drift < 0) drift = -drift;
        if (drift < HLM_MAX_DRIFT_SECONDS) {
            *now_utc = local;
            return HLM_OK;
        }
        /* drifted: the NTP answer itself is trustworthy */
        *now_utc = ntp_time;
        return HLM_OK;
    }

    if (sntp_query("pool.ntp.org", HLM_NTP_TIMEOUT_MS, &ntp_time) == 0) {
        *now_utc = ntp_time;
        return HLM_OK;
    }

    return HLM_E_HTTP; /* caller falls back to GET DateTime, then local */
}

hlm_timesync hlm_timesync_win(void)
{
    hlm_timesync t;
    t.now = timesync_win_now;
    t.user = 0;
    return t;
}

/* ------------------------------------------------------------------ */
/* Machine identity                                                    */
/* ------------------------------------------------------------------ */

/* SMBIOS raw table layout per the RSMB firmware table. */
typedef struct {
    BYTE Used20CallingMethod;
    BYTE SMBIOSMajorVersion;
    BYTE SMBIOSMinorVersion;
    BYTE DmiRevision;
    DWORD Length;
    BYTE SMBIOSTableData[1];
} raw_smbios;

/* Fetch string `index` (1-based) trailing an SMBIOS structure. */
static const char *smbios_string(const BYTE *strings, const BYTE *end, int index)
{
    int i;
    const BYTE *p = strings;

    if (index <= 0) return NULL;
    for (i = 1; p < end; i++) {
        size_t len = strnlen((const char *)p, (size_t)(end - p));
        if (len == (size_t)(end - p)) return NULL; /* no NUL before end */
        if (len == 0) return NULL; /* end of string-set */
        if (i == index) return (const char *)p;
        p += len + 1;
    }
    return NULL;
}

/* Baseboard (SMBIOS type 2) serial number -> out. */
static int smbios_baseboard_serial(char *out, size_t out_len)
{
    UINT size;
    BYTE *buf;
    raw_smbios *smb;
    const BYTE *p, *end;
    int found = 0;

    size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size <= offsetof(raw_smbios, SMBIOSTableData) || size > 1024 * 1024)
        return -1;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (buf == NULL) return -1;
    if (GetSystemFirmwareTable('RSMB', 0, buf, size) != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }

    smb = (raw_smbios *)buf;
    p = smb->SMBIOSTableData;
    {
        /* never trust the firmware-reported Length past the allocation */
        size_t cap = size - offsetof(raw_smbios, SMBIOSTableData);
        end = p + (smb->Length <= cap ? smb->Length : cap);
    }

    while (p + 4 <= end) {
        BYTE type = p[0];
        BYTE len = p[1];
        const BYTE *strings;
        const BYTE *q;

        if (len < 4 || len > (size_t)(end - p)) break;
        strings = p + len;
        q = strings;

        /* find the end of this structure's string-set (double NUL) */
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) q++;
        if (q + 1 >= end) break; /* truncated table: no terminator */
        q += 2;

        if (type == 2 && len > 0x07) {
            const char *serial = smbios_string(strings, end, p[0x07]);
            if (serial != NULL && serial[0] != '\0') {
                size_t sl = strlen(serial);
                if (sl < out_len) {
                    memcpy(out, serial, sl + 1);
                    found = 1;
                }
            }
            break;
        }
        p = q;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return found ? 0 : -1;
}

/* CPUID leaf 1 -> the 16-hex-char string WMI reports as ProcessorId. */
static void processor_id(char out[17])
{
    int regs[4] = { 0, 0, 0, 0 };
    __cpuid(regs, 1);
    /* EDX (feature flags) then EAX (signature), uppercase hex. */
    snprintf(out, 17, "%08X%08X", (unsigned)regs[3], (unsigned)regs[0]);
}

int hlm_machine_id_win(char *out, size_t out_len)
{
    char serial[128];
    char cpu[17];
    const char *components[2];

    if (smbios_baseboard_serial(serial, sizeof(serial)) != 0)
        return HLM_E_ARG; /* no baseboard serial exposed — caller must supply one */
    processor_id(cpu);

    /* DeviceId orders components by name: MotherboardSerialNumber < ProcessorId */
    components[0] = serial;
    components[1] = cpu;
    return hlm_fingerprint(components, 2, out, out_len);
}

int hlm_machine_name_win(char *out, size_t out_len)
{
    DWORD n = (DWORD)out_len;
    if (!GetComputerNameA(out, &n)) return HLM_E_ARG;
    return HLM_OK;
}

#endif /* _WIN32 */
