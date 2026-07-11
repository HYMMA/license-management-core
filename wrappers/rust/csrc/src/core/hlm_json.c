#include "hlm_json.h"

#include <string.h>

/* ---------- tokenizer ---------- */

typedef struct {
    const char *src;
    size_t len;
    size_t pos;
    hlm_json_tok *toks;
    int max_toks;
    int count;
    int parent;
} parser_state;

static hlm_json_tok *alloc_tok(parser_state *p)
{
    hlm_json_tok *t;
    if (p->count >= p->max_toks) return NULL;
    t = &p->toks[p->count++];
    t->type = HLM_JSON_UNDEFINED;
    t->start = t->end = -1;
    t->size = 0;
    t->parent = p->parent;
    return t;
}

static int parse_string_tok(parser_state *p)
{
    hlm_json_tok *t = alloc_tok(p);
    size_t start;

    if (t == NULL) return -1;
    p->pos++; /* opening quote */
    start = p->pos;

    while (p->pos < p->len) {
        char c = p->src[p->pos];
        if (c == '"') {
            t->type = HLM_JSON_STRING;
            t->start = (int)start;
            t->end = (int)p->pos;
            p->pos++;
            return 0;
        }
        if (c == '\\') {
            p->pos++;
            if (p->pos >= p->len) return -3;
            switch (p->src[p->pos]) {
            case '"': case '\\': case '/': case 'b': case 'f':
            case 'n': case 'r': case 't':
                break;
            case 'u': {
                int i;
                for (i = 0; i < 4; i++) {
                    p->pos++;
                    if (p->pos >= p->len) return -3;
                    c = p->src[p->pos];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F')))
                        return -2;
                }
                break;
            }
            default:
                return -2;
            }
        } else if ((unsigned char)c < 0x20) {
            return -2; /* raw control char inside string */
        }
        p->pos++;
    }
    return -3;
}

static int parse_primitive_tok(parser_state *p)
{
    hlm_json_tok *t = alloc_tok(p);
    size_t start = p->pos;

    if (t == NULL) return -1;

    while (p->pos < p->len) {
        char c = p->src[p->pos];
        if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' ||
            c == '\r' || c == '\n' || c == ':') {
            break;
        }
        if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7f) return -2;
        p->pos++;
    }
    if (p->pos == start) return -2;

    t->type = HLM_JSON_PRIMITIVE;
    t->start = (int)start;
    t->end = (int)p->pos;
    return 0;
}

int hlm_json_parse(const char *src, size_t len, hlm_json_tok *toks, int max_toks)
{
    parser_state p;
    int depth = 0;

    p.src = src;
    p.len = len;
    p.pos = 0;
    p.toks = toks;
    p.max_toks = max_toks;
    p.count = 0;
    p.parent = -1;

    while (p.pos < p.len) {
        char c = p.src[p.pos];
        hlm_json_tok *t;

        switch (c) {
        case '{': case '[': {
            t = alloc_tok(&p);
            if (t == NULL) return -1;
            if (p.parent >= 0) {
                hlm_json_tok *par = &p.toks[p.parent];
                /* Object values/array elements bump the container size;
                 * keys already bumped it, values attach to the key. */
                if (par->type == HLM_JSON_ARRAY ||
                    (par->type == HLM_JSON_OBJECT)) {
                    par->size++;
                }
            }
            t->type = (c == '{') ? HLM_JSON_OBJECT : HLM_JSON_ARRAY;
            t->start = (int)p.pos;
            p.parent = p.count - 1;
            depth++;
            p.pos++;
            break;
        }
        case '}': case ']': {
            hlm_json_type want = (c == '}') ? HLM_JSON_OBJECT : HLM_JSON_ARRAY;
            /* an object/array value leaves its KEY as parent — pop it first */
            if (p.parent >= 0 && p.toks[p.parent].type == HLM_JSON_STRING) {
                p.parent = p.toks[p.parent].parent;
            }
            if (p.parent < 0) return -2;
            t = &p.toks[p.parent];
            if (t->type != want || t->end != -1) return -2;
            t->end = (int)p.pos + 1;
            p.parent = t->parent;
            depth--;
            p.pos++;
            break;
        }
        case '"': {
            int r;
            int is_key = 0;
            if (p.parent >= 0 && p.toks[p.parent].type == HLM_JSON_OBJECT) {
                /* Inside an object: a string at even position is a key.
                 * Keys re-parent the following value to themselves. */
                is_key = 1;
            }
            r = parse_string_tok(&p);
            if (r < 0) return r;
            if (p.parent >= 0) {
                if (is_key) {
                    p.toks[p.parent].size++;
                    /* The key token becomes parent of its value. */
                    p.parent = p.count - 1;
                } else if (p.toks[p.parent].type == HLM_JSON_ARRAY) {
                    p.toks[p.parent].size++;
                } else if (p.toks[p.parent].type == HLM_JSON_STRING) {
                    /* string value under a key */
                    p.toks[p.parent].size++;
                    p.parent = p.toks[p.parent].parent;
                }
            }
            break;
        }
        case ' ': case '\t': case '\r': case '\n':
            p.pos++;
            break;
        case ':':
            p.pos++;
            break;
        case ',':
            /* If current parent is a key (string), pop back to the object. */
            if (p.parent >= 0 && p.toks[p.parent].type == HLM_JSON_STRING) {
                p.parent = p.toks[p.parent].parent;
            }
            p.pos++;
            break;
        default: {
            int r = parse_primitive_tok(&p);
            if (r < 0) return r;
            if (p.parent >= 0) {
                if (p.toks[p.parent].type == HLM_JSON_ARRAY) {
                    p.toks[p.parent].size++;
                } else if (p.toks[p.parent].type == HLM_JSON_STRING) {
                    p.toks[p.parent].size++;
                    p.parent = p.toks[p.parent].parent;
                } else if (p.toks[p.parent].type == HLM_JSON_OBJECT) {
                    return -2; /* bare primitive where a key belongs */
                }
            }
            break;
        }
        }
    }

    if (depth != 0) return -3;
    if (p.count == 0) return -2;
    return p.count;
}

void hlm_json_doc_init(hlm_json_doc *doc, const char *src, size_t len,
                       hlm_json_tok *toks, int count)
{
    doc->src = src;
    doc->src_len = len;
    doc->toks = toks;
    doc->count = count;
}

/* ---------- navigation ---------- */

int hlm_json_member(const hlm_json_doc *doc, int obj, const char *key)
{
    int i;
    size_t klen = strlen(key);

    if (obj < 0 || obj >= doc->count) return -1;
    if (doc->toks[obj].type != HLM_JSON_OBJECT) return -1;

    for (i = obj + 1; i < doc->count; i++) {
        const hlm_json_tok *t = &doc->toks[i];
        if (t->parent == obj && t->type == HLM_JSON_STRING) {
            /* keys are exactly the strings whose parent is the object */
            size_t len = (size_t)(t->end - t->start);
            if (len == klen && memcmp(doc->src + t->start, key, klen) == 0) {
                /* value = first token parented to this key */
                int j;
                for (j = i + 1; j < doc->count; j++) {
                    if (doc->toks[j].parent == i) return j;
                }
                return -1;
            }
        }
    }
    return -1;
}

int hlm_json_element(const hlm_json_doc *doc, int arr, int idx)
{
    int i, n = 0;

    if (arr < 0 || arr >= doc->count) return -1;
    if (doc->toks[arr].type != HLM_JSON_ARRAY) return -1;

    for (i = arr + 1; i < doc->count; i++) {
        if (doc->toks[i].parent == arr) {
            if (n == idx) return i;
            n++;
        }
    }
    return -1;
}

int hlm_json_is_null(const hlm_json_doc *doc, int tok)
{
    const hlm_json_tok *t;
    if (tok < 0 || tok >= doc->count) return 1;
    t = &doc->toks[tok];
    return t->type == HLM_JSON_PRIMITIVE && (t->end - t->start) == 4 &&
           memcmp(doc->src + t->start, "null", 4) == 0;
}

const char *hlm_json_raw(const hlm_json_doc *doc, int tok, size_t *len_out)
{
    if (tok < 0 || tok >= doc->count) return NULL;
    if (len_out) *len_out = (size_t)(doc->toks[tok].end - doc->toks[tok].start);
    return doc->src + doc->toks[tok].start;
}

/* ---------- string unescape ---------- */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t utf8_emit(uint32_t cp, char *out, size_t cap, size_t at)
{
    if (cp < 0x80) {
        if (at + 1 > cap) return (size_t)-1;
        out[at++] = (char)cp;
    } else if (cp < 0x800) {
        if (at + 2 > cap) return (size_t)-1;
        out[at++] = (char)(0xc0 | (cp >> 6));
        out[at++] = (char)(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
        if (at + 3 > cap) return (size_t)-1;
        out[at++] = (char)(0xe0 | (cp >> 12));
        out[at++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[at++] = (char)(0x80 | (cp & 0x3f));
    } else {
        if (at + 4 > cap) return (size_t)-1;
        out[at++] = (char)(0xf0 | (cp >> 18));
        out[at++] = (char)(0x80 | ((cp >> 12) & 0x3f));
        out[at++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[at++] = (char)(0x80 | (cp & 0x3f));
    }
    return at;
}

size_t hlm_json_string(const hlm_json_doc *doc, int tok, char *out, size_t out_cap)
{
    const hlm_json_tok *t;
    size_t i, o = 0, len;
    const char *s;

    if (tok < 0 || tok >= doc->count) return (size_t)-1;
    t = &doc->toks[tok];
    if (t->type != HLM_JSON_STRING) return (size_t)-1;

    s = doc->src + t->start;
    len = (size_t)(t->end - t->start);

    for (i = 0; i < len; i++) {
        char c = s[i];
        if (c != '\\') {
            if (o + 1 > out_cap) return (size_t)-1;
            out[o++] = c;
            continue;
        }
        i++;
        if (i >= len) return (size_t)-1;
        switch (s[i]) {
        case '"':  c = '"';  goto put;
        case '\\': c = '\\'; goto put;
        case '/':  c = '/';  goto put;
        case 'b':  c = '\b'; goto put;
        case 'f':  c = '\f'; goto put;
        case 'n':  c = '\n'; goto put;
        case 'r':  c = '\r'; goto put;
        case 't':  c = '\t'; goto put;
        case 'u': {
            uint32_t cp = 0;
            int k;
            if (i + 4 >= len + 1) return (size_t)-1;
            for (k = 0; k < 4; k++) {
                int h = hexval(s[i + 1 + k]);
                if (h < 0) return (size_t)-1;
                cp = (cp << 4) | (uint32_t)h;
            }
            i += 4;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                /* high surrogate — need \uDC00-\uDFFF next */
                uint32_t lo = 0;
                if (i + 6 >= len + 1 || s[i + 1] != '\\' || s[i + 2] != 'u')
                    return (size_t)-1;
                for (k = 0; k < 4; k++) {
                    int h = hexval(s[i + 3 + k]);
                    if (h < 0) return (size_t)-1;
                    lo = (lo << 4) | (uint32_t)h;
                }
                if (lo < 0xdc00 || lo > 0xdfff) return (size_t)-1;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                i += 6;
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                return (size_t)-1; /* lone low surrogate */
            }
            o = utf8_emit(cp, out, out_cap, o);
            if (o == (size_t)-1) return (size_t)-1;
            continue;
        }
        default:
            return (size_t)-1;
        }
    put:
        if (o + 1 > out_cap) return (size_t)-1;
        out[o++] = c;
    }

    if (o + 1 > out_cap) return (size_t)-1;
    out[o] = '\0';
    return o;
}

/* ---------- primitives ---------- */

int hlm_json_bool(const hlm_json_doc *doc, int tok, int *out)
{
    size_t len;
    const char *s = hlm_json_raw(doc, tok, &len);
    if (s == NULL || doc->toks[tok].type != HLM_JSON_PRIMITIVE) return -1;
    if (len == 4 && memcmp(s, "true", 4) == 0) { *out = 1; return 0; }
    if (len == 5 && memcmp(s, "false", 5) == 0) { *out = 0; return 0; }
    return -1;
}

int hlm_json_int64(const hlm_json_doc *doc, int tok, int64_t *out)
{
    size_t len, i = 0;
    int neg = 0;
    int64_t v = 0;
    const char *s = hlm_json_raw(doc, tok, &len);

    if (s == NULL || doc->toks[tok].type != HLM_JSON_PRIMITIVE || len == 0)
        return -1;
    if (s[0] == '-') { neg = 1; i = 1; }
    if (i >= len) return -1;
    for (; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1; /* no float support needed */
        if (v > (INT64_MAX - (s[i] - '0')) / 10) return -1;
        v = v * 10 + (s[i] - '0');
    }
    *out = neg ? -v : v;
    return 0;
}

/* ---------- ISO 8601 ---------- */

static int read_digits(const char *s, size_t len, size_t *i, int count, int *out)
{
    int v = 0, k;
    for (k = 0; k < count; k++) {
        if (*i >= len || s[*i] < '0' || s[*i] > '9') return -1;
        v = v * 10 + (s[*i] - '0');
        (*i)++;
    }
    *out = v;
    return 0;
}

/* days from civil date (Howard Hinnant's algorithm), valid for all Gregorian dates */
static int64_t days_from_civil(int y, int m, int d)
{
    int64_t era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

int hlm_parse_iso8601(const char *s, size_t len, int64_t *epoch_out)
{
    size_t i = 0;
    int year, mon, day, hour = 0, min = 0, sec = 0;
    int64_t offset = 0;

    if (read_digits(s, len, &i, 4, &year) < 0) return -1;
    if (i >= len || s[i] != '-') return -1;
    i++;
    if (read_digits(s, len, &i, 2, &mon) < 0) return -1;
    if (i >= len || s[i] != '-') return -1;
    i++;
    if (read_digits(s, len, &i, 2, &day) < 0) return -1;

    if (i < len && (s[i] == 'T' || s[i] == 't' || s[i] == ' ')) {
        i++;
        if (read_digits(s, len, &i, 2, &hour) < 0) return -1;
        if (i >= len || s[i] != ':') return -1;
        i++;
        if (read_digits(s, len, &i, 2, &min) < 0) return -1;
        if (i < len && s[i] == ':') {
            i++;
            if (read_digits(s, len, &i, 2, &sec) < 0) return -1;
        }
        if (i < len && s[i] == '.') {
            i++;
            while (i < len && s[i] >= '0' && s[i] <= '9') i++; /* truncate */
        }
        if (i < len) {
            if (s[i] == 'Z' || s[i] == 'z') {
                i++;
            } else if (s[i] == '+' || s[i] == '-') {
                int oh, om = 0;
                int sign = (s[i] == '-') ? -1 : 1;
                i++;
                if (read_digits(s, len, &i, 2, &oh) < 0) return -1;
                if (i < len && s[i] == ':') {
                    i++;
                    if (read_digits(s, len, &i, 2, &om) < 0) return -1;
                }
                offset = (int64_t)sign * (oh * 3600 + om * 60);
            }
        }
    }

    if (i != len) return -1;
    if (mon < 1 || mon > 12 || day < 1 || day > 31) return -1;
    if (hour > 23 || min > 59 || sec > 60) return -1;

    *epoch_out = days_from_civil(year, mon, day) * 86400
               + hour * 3600 + min * 60 + sec - offset;
    return 0;
}

int hlm_json_datetime(const hlm_json_doc *doc, int tok, int64_t *epoch_out)
{
    char buf[64];
    size_t n = hlm_json_string(doc, tok, buf, sizeof(buf));
    if (n == (size_t)-1) return -1;
    return hlm_parse_iso8601(buf, n, epoch_out);
}
