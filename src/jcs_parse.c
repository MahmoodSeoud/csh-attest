/*
 * JCS-canonical JSON parser. Recursive-descent over a (ptr, end) cursor.
 * See jcs_parse.h for the accepted subset.
 *
 * Failure model: every parse_* function leaves `out` in a state where
 * jcsp_value_free is safe (default-zeroed values are freeable). Type is set
 * AFTER allocations succeed; on early failure type stays at the parse_value
 * default (JCSP_UINT, value 0) which has nothing to free.
 */

#include "jcs_parse.h"

#include <stdlib.h>
#include <string.h>

#include "jcs.h"

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} cursor_t;

/* ------------------------------------------------------------------ */
/* Cursor primitives.                                                 */
/* ------------------------------------------------------------------ */

static int peek(const cursor_t *c, uint8_t *b)
{
    if (c->p >= c->end) {
        return -1;
    }
    *b = *c->p;
    return 0;
}

static int consume(cursor_t *c, uint8_t expected)
{
    uint8_t b;
    if (peek(c, &b) < 0 || b != expected) {
        return -1;
    }
    c->p++;
    return 0;
}

static int hex_nibble(uint8_t b)
{
    if (b >= '0' && b <= '9') {
        return b - '0';
    }
    /* JCS emitter uses lowercase hex only; reject uppercase to enforce
     * canonical input. */
    if (b >= 'a' && b <= 'f') {
        return 10 + (b - 'a');
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Growable byte buffer for string-decoding scratch space.            */
/* ------------------------------------------------------------------ */

struct strbuf {
    char *data;
    size_t len;
    size_t cap;
};

static int strbuf_append(struct strbuf *b, uint8_t byte)
{
    /* +1 reserves room for the trailing NUL we install at finalize. */
    if (b->len + 1 >= b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 16;
        char *new_data = realloc(b->data, new_cap);
        if (new_data == NULL) {
            return -1;
        }
        b->data = new_data;
        b->cap = new_cap;
    }
    b->data[b->len++] = (char)byte;
    return 0;
}

/* ------------------------------------------------------------------ */
/* String parser. Decodes RFC 8785 §3.2.2.2 escapes; rejects raw      */
/* control bytes and any non-canonical escape form.                   */
/* ------------------------------------------------------------------ */

static int parse_string_raw(cursor_t *c, char **out_bytes, size_t *out_len)
{
    if (consume(c, '"') < 0) {
        return -1;
    }

    struct strbuf sb = {0};

    while (c->p < c->end) {
        uint8_t b = *c->p;

        if (b == '"') {
            c->p++;
            /* Always allocate a finalized buffer, even for empty strings,
             * so callers get a non-NULL NUL-terminated pointer. */
            if (sb.data == NULL) {
                sb.data = malloc(1);
                if (sb.data == NULL) {
                    return -1;
                }
            }
            sb.data[sb.len] = '\0';
            *out_bytes = sb.data;
            *out_len = sb.len;
            return 0;
        }

        if (b == '\\') {
            c->p++;
            if (c->p >= c->end) {
                goto fail;
            }
            uint8_t esc = *c->p++;
            uint8_t decoded;
            switch (esc) {
            case '"':  decoded = 0x22; break;
            case '\\': decoded = 0x5C; break;
            case 'b':  decoded = 0x08; break;
            case 'f':  decoded = 0x0C; break;
            case 'n':  decoded = 0x0A; break;
            case 'r':  decoded = 0x0D; break;
            case 't':  decoded = 0x09; break;
            case 'u': {
                /*
                 * RFC 8785 mandates \u00XX form ONLY for control bytes that
                 * lack a named shortcut (0x00-0x07, 0x0B, 0x0E-0x1F). Reject
                 * anything else: * (printable) is non-canonical, as is
                 * \u00XX where XX ∈ {08, 09, 0A, 0C, 0D} (those use the
                 * named shortcut).
                 */
                if (c->p + 4 > c->end) {
                    goto fail;
                }
                if (c->p[0] != '0' || c->p[1] != '0') {
                    goto fail;
                }
                int hi = hex_nibble(c->p[2]);
                int lo = hex_nibble(c->p[3]);
                if (hi < 0 || lo < 0) {
                    goto fail;
                }
                uint8_t v = (uint8_t)((hi << 4) | lo);
                if (v >= 0x20 ||
                    v == 0x08 || v == 0x09 || v == 0x0A ||
                    v == 0x0C || v == 0x0D) {
                    goto fail;
                }
                decoded = v;
                c->p += 4;
                break;
            }
            default:
                goto fail;
            }
            if (strbuf_append(&sb, decoded) < 0) {
                goto fail;
            }
            continue;
        }

        /* Bare control bytes 0x00-0x1F MUST be escaped per RFC 8785. */
        if (b < 0x20) {
            goto fail;
        }

        /* Printable ASCII or UTF-8 continuation byte: pass through verbatim.
         * No UTF-8 validation here — adapter authors are responsible for
         * passing well-formed UTF-8 to the emitter, and the emitter itself
         * does no validation either. */
        if (strbuf_append(&sb, b) < 0) {
            goto fail;
        }
        c->p++;
    }

fail:
    free(sb.data);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Uint parser. Single 0 OR [1-9][0-9]* up to 2^53.                   */
/* ------------------------------------------------------------------ */

static int parse_uint(cursor_t *c, uint64_t *out)
{
    uint8_t b;
    if (peek(c, &b) < 0 || b < '0' || b > '9') {
        return -1;
    }

    if (b == '0') {
        c->p++;
        /* Reject "01", "00", "0123" — leading-zero forms are non-canonical. */
        if (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
            return -1;
        }
        *out = 0;
        return 0;
    }

    uint64_t v = 0;
    const uint64_t cap = ((uint64_t)1) << 53;
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        if (v > cap / 10) {
            return -1;
        }
        v *= 10;
        uint64_t digit = (uint64_t)(*c->p - '0');
        if (v > cap - digit) {
            return -1;
        }
        v += digit;
        c->p++;
    }
    *out = v;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Object + value mutual recursion.                                   */
/* ------------------------------------------------------------------ */

static int parse_value(cursor_t *c, struct jcsp_value *out);

static int parse_array(cursor_t *c, struct jcsp_value *out)
{
    /*
     * Set type/zeroed payload immediately so any early-failure return
     * leaves `out` walkable by jcsp_value_free.
     */
    out->type = JCSP_ARRAY;
    out->u.array.items = NULL;
    out->u.array.n = 0;
    size_t cap = 0;

    if (consume(c, '[') < 0) {
        return -1;
    }

    /* Empty array short-circuit. */
    uint8_t b;
    if (peek(c, &b) < 0) {
        return -1;
    }
    if (b == ']') {
        c->p++;
        return 0;
    }

    for (;;) {
        if (out->u.array.n == cap) {
            size_t new_cap = cap ? cap * 2 : 4;
            struct jcsp_value *new_arr = realloc(
                out->u.array.items, new_cap * sizeof(struct jcsp_value));
            if (new_arr == NULL) {
                return -1;
            }
            out->u.array.items = new_arr;
            cap = new_cap;
        }

        struct jcsp_value *v = &out->u.array.items[out->u.array.n];
        memset(v, 0, sizeof(*v));
        v->type = JCSP_UINT;
        v->u.uint = 0;

        if (parse_value(c, v) < 0) {
            /* Bump n so the freshly-failed slot gets walked by free(). */
            out->u.array.n++;
            return -1;
        }
        out->u.array.n++;

        if (peek(c, &b) < 0) {
            return -1;
        }
        if (b == ']') {
            c->p++;
            return 0;
        }
        if (b != ',') {
            return -1;
        }
        c->p++;
        /* No trailing comma allowed: next iteration must read a value. */
    }
}

static int parse_object(cursor_t *c, struct jcsp_value *out)
{
    /*
     * Set type/zeroed payload immediately so any early-failure return
     * leaves `out` in a state jcsp_value_free can walk.
     */
    out->type = JCSP_OBJECT;
    out->u.object.members = NULL;
    out->u.object.n = 0;
    size_t cap = 0;

    if (consume(c, '{') < 0) {
        return -1;
    }

    /* Empty object short-circuit. */
    uint8_t b;
    if (peek(c, &b) < 0) {
        return -1;
    }
    if (b == '}') {
        c->p++;
        return 0;
    }

    char prev_key[128] = {0};
    bool have_prev = false;

    for (;;) {
        if (out->u.object.n == cap) {
            size_t new_cap = cap ? cap * 2 : 4;
            struct jcsp_member *new_arr = realloc(
                out->u.object.members, new_cap * sizeof(struct jcsp_member));
            if (new_arr == NULL) {
                return -1;
            }
            out->u.object.members = new_arr;
            cap = new_cap;
        }

        char *key = NULL;
        size_t key_len = 0;
        if (parse_string_raw(c, &key, &key_len) < 0) {
            return -1;
        }

        /*
         * Sortedness: strictly greater than previous in-scope key. strcmp
         * matches the emitter's enforcement (jcs.c::jcs_pre_key) byte-for-
         * byte — both treat keys without embedded NULs identically.
         */
        if (have_prev && strcmp(key, prev_key) <= 0) {
            free(key);
            return -1;
        }
        strncpy(prev_key, key, sizeof(prev_key) - 1);
        prev_key[sizeof(prev_key) - 1] = '\0';
        have_prev = true;

        if (consume(c, ':') < 0) {
            free(key);
            return -1;
        }

        struct jcsp_member *m = &out->u.object.members[out->u.object.n];
        m->key = key;
        memset(&m->value, 0, sizeof(m->value)); /* default JCSP_STRING(NULL,0) — set type explicitly. */
        m->value.type = JCSP_UINT;
        m->value.u.uint = 0;

        if (parse_value(c, &m->value) < 0) {
            /*
             * Bump n so jcsp_value_free walks this slot on cleanup. The
             * value is left in whatever state parse_value's failure path
             * established — its contract is "freeable on failure too".
             */
            out->u.object.n++;
            return -1;
        }
        out->u.object.n++;

        if (peek(c, &b) < 0) {
            return -1;
        }
        if (b == '}') {
            c->p++;
            return 0;
        }
        if (b != ',') {
            return -1;
        }
        c->p++;
        /* No trailing comma allowed: next iteration must read a key. */
    }
}

static int parse_value(cursor_t *c, struct jcsp_value *out)
{
    /* Default safe state for partial-failure cleanup. */
    out->type = JCSP_UINT;
    out->u.uint = 0;

    uint8_t b;
    if (peek(c, &b) < 0) {
        return -1;
    }

    if (b == '{') {
        return parse_object(c, out);
    }
    if (b == '[') {
        return parse_array(c, out);
    }
    if (b == '"') {
        char *bytes = NULL;
        size_t len = 0;
        if (parse_string_raw(c, &bytes, &len) < 0) {
            return -1;
        }
        out->type = JCSP_STRING;
        out->u.string.bytes = bytes;
        out->u.string.len = len;
        return 0;
    }
    if (b >= '0' && b <= '9') {
        uint64_t v;
        if (parse_uint(c, &v) < 0) {
            return -1;
        }
        out->type = JCSP_UINT;
        out->u.uint = v;
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Public API.                                                        */
/* ------------------------------------------------------------------ */

int jcsp_parse(const uint8_t *bytes, size_t len, struct jcsp_value *out)
{
    cursor_t c = {bytes, bytes + len};
    /* Default-zero the destination so caller's free path works even if the
     * very first byte is invalid. */
    out->type = JCSP_UINT;
    out->u.uint = 0;

    if (parse_value(&c, out) < 0) {
        jcsp_value_free(out);
        return -1;
    }
    if (c.p != c.end) {
        /* Trailing bytes after a valid top-level value: not canonical. */
        jcsp_value_free(out);
        return -1;
    }
    return 0;
}

void jcsp_value_free(struct jcsp_value *v)
{
    if (v == NULL) {
        return;
    }
    switch (v->type) {
    case JCSP_STRING:
        free(v->u.string.bytes);
        break;
    case JCSP_UINT:
        break;
    case JCSP_OBJECT:
        for (size_t i = 0; i < v->u.object.n; i++) {
            free(v->u.object.members[i].key);
            jcsp_value_free(&v->u.object.members[i].value);
        }
        free(v->u.object.members);
        break;
    case JCSP_ARRAY:
        for (size_t i = 0; i < v->u.array.n; i++) {
            jcsp_value_free(&v->u.array.items[i]);
        }
        free(v->u.array.items);
        break;
    }
    /* Reset to a re-freeable state for safety against double-free. */
    v->type = JCSP_UINT;
    v->u.uint = 0;
}

/* ------------------------------------------------------------------ */
/* Re-emit through the canonical emitter.                             */
/* ------------------------------------------------------------------ */

static int emit_into(const struct jcsp_value *v, struct attest_emitter *em);

static int emit_into(const struct jcsp_value *v, struct attest_emitter *em)
{
    switch (v->type) {
    case JCSP_STRING:
        return em->ops->value_string(em->ctx, v->u.string.bytes);
    case JCSP_UINT:
        return em->ops->value_uint(em->ctx, v->u.uint);
    case JCSP_OBJECT: {
        int rc = em->ops->object_open(em->ctx);
        if (rc < 0) {
            return rc;
        }
        for (size_t i = 0; i < v->u.object.n; i++) {
            rc = em->ops->key(em->ctx, v->u.object.members[i].key);
            if (rc < 0) {
                return rc;
            }
            rc = emit_into(&v->u.object.members[i].value, em);
            if (rc < 0) {
                return rc;
            }
        }
        return em->ops->object_close(em->ctx);
    }
    case JCSP_ARRAY: {
        int rc = em->ops->array_open(em->ctx);
        if (rc < 0) {
            return rc;
        }
        for (size_t i = 0; i < v->u.array.n; i++) {
            rc = emit_into(&v->u.array.items[i], em);
            if (rc < 0) {
                return rc;
            }
        }
        return em->ops->array_close(em->ctx);
    }
    }
    return -1;
}

int jcsp_emit(const struct jcsp_value *v, struct jcs_buffer *out)
{
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_canonical_init(&em, &ctx, out);
    return emit_into(v, &em);
}

/* ------------------------------------------------------------------ */
/* Structural equality.                                               */
/* ------------------------------------------------------------------ */

bool jcsp_value_equals(const struct jcsp_value *a, const struct jcsp_value *b)
{
    if (a->type != b->type) {
        return false;
    }
    switch (a->type) {
    case JCSP_STRING:
        if (a->u.string.len != b->u.string.len) {
            return false;
        }
        return memcmp(a->u.string.bytes, b->u.string.bytes,
                      a->u.string.len) == 0;
    case JCSP_UINT:
        return a->u.uint == b->u.uint;
    case JCSP_OBJECT:
        if (a->u.object.n != b->u.object.n) {
            return false;
        }
        for (size_t i = 0; i < a->u.object.n; i++) {
            const struct jcsp_member *am = &a->u.object.members[i];
            const struct jcsp_member *bm = &b->u.object.members[i];
            if (strcmp(am->key, bm->key) != 0) {
                return false;
            }
            if (!jcsp_value_equals(&am->value, &bm->value)) {
                return false;
            }
        }
        return true;
    case JCSP_ARRAY:
        if (a->u.array.n != b->u.array.n) {
            return false;
        }
        for (size_t i = 0; i < a->u.array.n; i++) {
            if (!jcsp_value_equals(&a->u.array.items[i],
                                   &b->u.array.items[i])) {
                return false;
            }
        }
        return true;
    }
    return false;
}
