/* Windows ports: WinHTTP transport + machine identity.
 *
 * Machine identity reproduces the .NET SDK's DeviceId pipeline without WMI:
 *   Win32_BaseBoard.SerialNumber   -> SMBIOS type 2 serial (GetSystemFirmwareTable)
 *   Win32_Processor.ProcessorId    -> CPUID leaf 1, "%08X%08X" of EDX,EAX
 * so the same physical machine registers as the SAME computer whether the
 * vendor ships the .NET SDK or this core.
 */
#if defined(_WIN32)

#include <windows.h>
#include <winhttp.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

#include "hymma/hlm.h"

#pragma comment(lib, "winhttp.lib")

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

    session = WinHttpOpen(L"hymma-lm-core/1.0",
                          WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == NULL) goto done;

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
    if (size == 0 || size > 1024 * 1024) return -1;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (buf == NULL) return -1;
    if (GetSystemFirmwareTable('RSMB', 0, buf, size) != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }

    smb = (raw_smbios *)buf;
    p = smb->SMBIOSTableData;
    end = p + smb->Length;

    while (p + 4 <= end) {
        BYTE type = p[0];
        BYTE len = p[1];
        const BYTE *strings = p + len;
        const BYTE *q = strings;

        if (len < 4) break;

        /* find the end of this structure's string-set (double NUL) */
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) q++;
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
