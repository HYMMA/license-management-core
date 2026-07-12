/* License payload parsing, status evaluation, fingerprinting.
 *
 * The payload is the JSON the server's JwsLicenseSigner emits: the
 * LicenseGetApiModel serialized by System.Text.Json with default (PascalCase)
 * property names and nulls omitted. Lookups tolerate camelCase too, so a
 * future serializer-options change cannot brick devices in the field.
 */
#include <string.h>

#include "hymma/hlm.h"
#include "hlm_json.h"
#include "hlm_sha256.h"

const char *hlm_status_str(hlm_status s)
{
    switch (s) {
    case HLM_STATUS_EXPIRED: return "Expired";
    case HLM_STATUS_VALID: return "Valid";
    case HLM_STATUS_VALID_TRIAL: return "ValidTrial";
    case HLM_STATUS_INVALID_TRIAL: return "InvalidTrial";
    case HLM_STATUS_RECEIPT_EXPIRED: return "ReceiptExpired";
    case HLM_STATUS_RECEIPT_UNREGISTERED: return "ReceiptUnregistered";
    default: return "Unknown";
    }
}

static hlm_status status_from_name(const char *s)
{
    if (strcmp(s, "Expired") == 0) return HLM_STATUS_EXPIRED;
    if (strcmp(s, "Valid") == 0) return HLM_STATUS_VALID;
    if (strcmp(s, "ValidTrial") == 0) return HLM_STATUS_VALID_TRIAL;
    if (strcmp(s, "InvalidTrial") == 0) return HLM_STATUS_INVALID_TRIAL;
    if (strcmp(s, "ReceiptExpired") == 0) return HLM_STATUS_RECEIPT_EXPIRED;
    if (strcmp(s, "ReceiptUnregistered") == 0) return HLM_STATUS_RECEIPT_UNREGISTERED;
    return HLM_STATUS_UNKNOWN;
}

/* Member lookup tolerating PascalCase and camelCase. */
static int member2(const hlm_json_doc *doc, int obj, const char *pascal,
                   const char *camel)
{
    int t = hlm_json_member(doc, obj, pascal);
    if (t < 0) t = hlm_json_member(doc, obj, camel);
    return t;
}

static void get_string(const hlm_json_doc *doc, int obj, const char *pascal,
                       const char *camel, char *out, size_t cap)
{
    int t = member2(doc, obj, pascal, camel);
    out[0] = '\0';
    if (t >= 0 && !hlm_json_is_null(doc, t)) {
        if (hlm_json_string(doc, t, out, cap) == (size_t)-1) out[0] = '\0';
    }
}

static int64_t get_time(const hlm_json_doc *doc, int obj, const char *pascal,
                        const char *camel)
{
    int64_t v;
    int t = member2(doc, obj, pascal, camel);
    if (t < 0 || hlm_json_is_null(doc, t)) return HLM_TIME_NONE;
    if (hlm_json_datetime(doc, t, &v) < 0) return HLM_TIME_NONE;
    return v;
}

int hlm_license_parse(const char *payload_json, size_t len, hlm_license *lic)
{
    /* A signed license is one object tree: license + receipt + product +
     * computer + vendor + metadata. 160 tokens is ~3x a real payload. */
    hlm_json_tok toks[160];
    hlm_json_doc doc;
    int ntok, t;

    if (payload_json == NULL || lic == NULL) return HLM_E_ARG;

    memset(lic, 0, sizeof(*lic));
    lic->trial_end = HLM_TIME_NONE;
    lic->first_paid_on = HLM_TIME_NONE;
    lic->expires = HLM_TIME_NONE;
    lic->created = HLM_TIME_NONE;
    lic->updated = HLM_TIME_NONE;
    lic->receipt.expires = HLM_TIME_NONE;
    lic->live_mode = 1;

    ntok = hlm_json_parse(payload_json, len, toks,
                          (int)(sizeof(toks) / sizeof(toks[0])));
    if (ntok <= 0) return HLM_E_FORMAT;
    hlm_json_doc_init(&doc, payload_json, len, toks, ntok);
    if (doc.toks[0].type != HLM_JSON_OBJECT) return HLM_E_FORMAT;

    get_string(&doc, 0, "Id", "id", lic->id, sizeof(lic->id));
    if (lic->id[0] == '\0') return HLM_E_FORMAT;

    {
        char status[32];
        get_string(&doc, 0, "Status", "status", status, sizeof(status));
        lic->server_status = status_from_name(status);
    }

    t = member2(&doc, 0, "LiveMode", "liveMode");
    if (t >= 0) {
        int b;
        if (hlm_json_bool(&doc, t, &b) == 0) lic->live_mode = b;
    }

    lic->trial_end = get_time(&doc, 0, "TrialEndDate", "trialEndDate");
    lic->first_paid_on = get_time(&doc, 0, "FirstPaidOn", "firstPaidOn");
    lic->expires = get_time(&doc, 0, "Expires", "expires");
    lic->created = get_time(&doc, 0, "Created", "created");
    lic->updated = get_time(&doc, 0, "Updated", "updated");

    t = member2(&doc, 0, "Receipt", "receipt");
    if (t >= 0 && !hlm_json_is_null(&doc, t)) {
        int qty_tok;
        lic->has_receipt = 1;
        get_string(&doc, t, "Id", "id", lic->receipt.id, sizeof(lic->receipt.id));
        get_string(&doc, t, "Code", "code", lic->receipt.code,
                   sizeof(lic->receipt.code));
        get_string(&doc, t, "BuyerEmail", "buyerEmail", lic->receipt.buyer_email,
                   sizeof(lic->receipt.buyer_email));
        lic->receipt.expires = get_time(&doc, t, "Expires", "expires");
        qty_tok = member2(&doc, t, "Qty", "qty");
        if (qty_tok >= 0) {
            int64_t q;
            if (hlm_json_int64(&doc, qty_tok, &q) == 0) lic->receipt.qty = (int)q;
        }
    }

    t = member2(&doc, 0, "Product", "product");
    if (t < 0 || hlm_json_is_null(&doc, t)) return HLM_E_FORMAT;
    get_string(&doc, t, "Id", "id", lic->product.id, sizeof(lic->product.id));
    get_string(&doc, t, "Name", "name", lic->product.name,
               sizeof(lic->product.name));
    {
        int v = member2(&doc, t, "Vendor", "vendor");
        if (v >= 0 && !hlm_json_is_null(&doc, v)) {
            get_string(&doc, v, "Id", "id", lic->product.vendor_id,
                       sizeof(lic->product.vendor_id));
            get_string(&doc, v, "Name", "name", lic->product.vendor_name,
                       sizeof(lic->product.vendor_name));
        }
    }
    if (lic->product.id[0] == '\0') return HLM_E_FORMAT;

    t = member2(&doc, 0, "Computer", "computer");
    if (t < 0 || hlm_json_is_null(&doc, t)) return HLM_E_FORMAT;
    get_string(&doc, t, "Id", "id", lic->computer.id, sizeof(lic->computer.id));
    get_string(&doc, t, "MacAddress", "macAddress", lic->computer.machine_id,
               sizeof(lic->computer.machine_id));
    get_string(&doc, t, "Name", "name", lic->computer.name,
               sizeof(lic->computer.name));

    /* Metadata: [{"Key":"k","Value":"v"}, ...] */
    t = member2(&doc, 0, "Metadata", "metadata");
    if (t >= 0 && !hlm_json_is_null(&doc, t) &&
        doc.toks[t].type == HLM_JSON_ARRAY) {
        int i;
        for (i = 0; i < HLM_MAX_METADATA; i++) {
            int el = hlm_json_element(&doc, t, i);
            if (el < 0) break;
            get_string(&doc, el, "Key", "key",
                       lic->metadata[lic->metadata_count].key,
                       sizeof(lic->metadata[0].key));
            get_string(&doc, el, "Value", "value",
                       lic->metadata[lic->metadata_count].value,
                       sizeof(lic->metadata[0].value));
            if (lic->metadata[lic->metadata_count].key[0] != '\0')
                lic->metadata_count++;
        }
    }

    return HLM_OK;
}

hlm_status hlm_license_status(const hlm_license *lic, int64_t now)
{
    /* 1. The license FILE's own expiry always wins (forces a re-fetch). */
    if (lic->expires != HLM_TIME_NONE && lic->expires <= now)
        return HLM_STATUS_EXPIRED;

    /* 2. Trust the signed server-computed status. */
    if (lic->server_status != HLM_STATUS_UNKNOWN)
        return lic->server_status;

    /* 3. Legacy fallback (status-less files), same rules as the .NET SDK. */
    if (lic->updated == HLM_TIME_NONE) {
        if (lic->trial_end != HLM_TIME_NONE && now < lic->trial_end)
            return HLM_STATUS_VALID_TRIAL;
        return HLM_STATUS_INVALID_TRIAL;
    }
    if (!lic->has_receipt)
        return HLM_STATUS_RECEIPT_UNREGISTERED;
    if (lic->receipt.expires != HLM_TIME_NONE && lic->receipt.expires <= now)
        return HLM_STATUS_RECEIPT_EXPIRED;
    return HLM_STATUS_VALID;
}

static int ascii_ieq(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

int hlm_license_check(const char *jws, size_t jws_len,
                      const hlm_public_key *keys, size_t key_count,
                      const hlm_crypto *crypto,
                      const char *expected_product_id,
                      const char *expected_machine_id,
                      int64_t now,
                      hlm_license *lic, hlm_status *status_out)
{
    uint8_t workbuf[HLM_CLIENT_BUF];
    const char *payload;
    size_t payload_len;
    int r;

    r = hlm_jws_verify(jws, jws_len, keys, key_count, crypto,
                       workbuf, sizeof(workbuf), &payload, &payload_len);
    if (r != HLM_OK) return r;

    r = hlm_license_parse(payload, payload_len, lic);
    if (r != HLM_OK) return r;

    if (expected_product_id != NULL &&
        !ascii_ieq(lic->product.id, expected_product_id))
        return HLM_E_PRODUCT_MISMATCH;
    if (expected_machine_id != NULL &&
        !ascii_ieq(lic->computer.machine_id, expected_machine_id))
        return HLM_E_COMPUTER_MISMATCH;

    if (status_out) *status_out = hlm_license_status(lic, now);
    return HLM_OK;
}

/* ------------------------------------------------------------------ */
/* Fingerprint                                                         */
/* ------------------------------------------------------------------ */

/* Crockford Base32, uppercase, no padding — matches DeviceId's
 * Base32ByteArrayEncoder: big-endian 5-bit groups, last group zero-padded. */
static void crockford_b32(const uint8_t *data, size_t len, char *out)
{
    static const char ALPHABET[33] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    size_t total_bits = len * 8;
    size_t i, o = 0;

    for (i = 0; i < total_bits; i += 5) {
        size_t byte_i = i / 8;
        size_t bit_off = i % 8;
        uint32_t chunk = (uint32_t)data[byte_i] << 8;
        if (byte_i + 1 < len) chunk |= data[byte_i + 1];
        chunk = (chunk >> (11 - bit_off)) & 0x1fu;
        out[o++] = ALPHABET[chunk];
    }
    out[o] = '\0';
}

int hlm_fingerprint(const char *const *components, size_t count,
                    char *out, size_t out_len)
{
    hlm_sha256_ctx ctx;
    uint8_t digest[HLM_SHA256_DIGEST_SIZE];
    size_t i;

    if (components == NULL || count == 0 || out == NULL) return HLM_E_ARG;
    if (out_len < 53) return HLM_E_BUFFER; /* 52 chars + NUL for a 32-byte hash */

    hlm_sha256_init(&ctx);
    for (i = 0; i < count; i++) {
        if (components[i] == NULL) return HLM_E_ARG;
        if (i > 0) hlm_sha256_update(&ctx, ",", 1);
        hlm_sha256_update(&ctx, components[i], strlen(components[i]));
    }
    hlm_sha256_final(&ctx, digest);

    crockford_b32(digest, sizeof(digest), out);
    return HLM_OK;
}
