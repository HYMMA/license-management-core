/* Portable default ports: stdio file storage and time(NULL) clock.
 * Embedded targets replace these with flash/RTC-backed implementations. */
#include <stdio.h>
#include <string.h>
#include <time.h>

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
    FILE *f = fopen(cfg->path, "wb");
    size_t n;

    if (f == NULL) return HLM_E_STORAGE;
    n = fwrite(data, 1, len, f);
    if (fclose(f) != 0 || n != len) return HLM_E_STORAGE;
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
