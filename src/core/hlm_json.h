/* Minimal JSON tokenizer (jsmn-style, non-allocating) + typed accessors.
 * Enough JSON to read a Hymma license payload and a JWK set — nothing more. */
#ifndef HLM_JSON_H
#define HLM_JSON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HLM_JSON_UNDEFINED = 0,
    HLM_JSON_OBJECT,
    HLM_JSON_ARRAY,
    HLM_JSON_STRING,
    HLM_JSON_PRIMITIVE /* number, true, false, null */
} hlm_json_type;

typedef struct {
    hlm_json_type type;
    int start;  /* index into source (for strings: first char inside quotes) */
    int end;    /* one past last char */
    int size;   /* members (object: pairs, array: elements) */
    int parent; /* token index of parent, -1 for root */
} hlm_json_tok;

typedef struct {
    const char *src;
    size_t src_len;
    const hlm_json_tok *toks; /* accessors never mutate tokens */
    int count;                /* tokens actually used */
} hlm_json_doc;

/* Tokenize `src` into caller-provided token array.
 * Returns token count (>0) or a negative error:
 *  -1 not enough tokens, -2 malformed input, -3 partial input. */
int hlm_json_parse(const char *src, size_t len, hlm_json_tok *toks, int max_toks);

/* Convenience: fill a doc struct after a successful parse. */
void hlm_json_doc_init(hlm_json_doc *doc, const char *src, size_t len,
                       hlm_json_tok *toks, int count);

/* Find direct member `key` of object token `obj`; returns the VALUE token index
 * or -1. Key comparison is case-sensitive and exact. */
int hlm_json_member(const hlm_json_doc *doc, int obj, const char *key);

/* Array element `i` of array token `arr`; returns token index or -1. */
int hlm_json_element(const hlm_json_doc *doc, int arr, int i);

/* True if token is the JSON literal null (or index is -1). */
int hlm_json_is_null(const hlm_json_doc *doc, int tok);

/* Unescape a STRING token into `out` (NUL-terminated UTF-8).
 * Returns bytes written (excl. NUL) or (size_t)-1 on error/overflow. */
size_t hlm_json_string(const hlm_json_doc *doc, int tok, char *out, size_t out_cap);

/* Raw (still-escaped) span of a string/primitive token. */
const char *hlm_json_raw(const hlm_json_doc *doc, int tok, size_t *len_out);

/* Primitive readers. Return 0 on success, -1 on type/parse error. */
int hlm_json_bool(const hlm_json_doc *doc, int tok, int *out);
int hlm_json_int64(const hlm_json_doc *doc, int tok, int64_t *out);

/* Parse an ISO-8601 timestamp string token ("2026-07-10T01:23:45.1234567Z",
 * offset "+hh:mm" or none — none is treated as UTC) into Unix epoch seconds.
 * Fractional seconds are truncated. Returns 0 on success. */
int hlm_json_datetime(const hlm_json_doc *doc, int tok, int64_t *epoch_out);

/* Same parser exposed for non-JSON callers. */
int hlm_parse_iso8601(const char *s, size_t len, int64_t *epoch_out);

#ifdef __cplusplus
}
#endif

#endif /* HLM_JSON_H */
