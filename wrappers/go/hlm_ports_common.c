/* Portable default ports: stdio file storage and time(NULL) clock.
 * Embedded targets replace these with flash/RTC-backed implementations. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "hymma/hlm.h"

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
