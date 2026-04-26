/*
 * JCS canonical emitter (RFC 8785 subset — see jcs.h for scope notes).
 */

#include "jcs.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Buffer.                                                            */
/* ------------------------------------------------------------------ */

void jcs_buffer_init(struct jcs_buffer *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void jcs_buffer_free(struct jcs_buffer *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static int jcs_buffer_append(struct jcs_buffer *b, const uint8_t *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t new_cap = b->cap ? b->cap : 256;
        while (new_cap < b->len + n) {
            new_cap *= 2;
        }
        uint8_t *new_data = realloc(b->data, new_cap);
        if (new_data == NULL) {
            return -1;
        }
        b->data = new_data;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

static int jcs_buffer_append_byte(struct jcs_buffer *b, uint8_t byte)
{
    return jcs_buffer_append(b, &byte, 1);
}

static int jcs_buffer_append_str(struct jcs_buffer *b, const char *s)
{
    return jcs_buffer_append(b, (const uint8_t *)s, strlen(s));
}

/* ------------------------------------------------------------------ */
/* String escape per RFC 8785 §3.2.2.2.                               */
/*                                                                    */
/* Bytes 0x00-0x1F: \uXXXX form, lowercase hex, EXCEPT special-named  */
/* shortcuts \b \f \n \r \t (0x08 0x0C 0x0A 0x0D 0x09).               */
/* Bytes 0x22 ("), 0x5C (\): backslash-escaped.                       */
/* Byte 0x7F (DEL): pass through (RFC 8785 specifies escape only for  */
/*   < 0x20).                                                         */
/* Bytes 0x20-0x7E (printable ASCII minus quote and backslash): raw.  */
/* Bytes 0x80+ (UTF-8 multibyte): raw.                                */
/* ------------------------------------------------------------------ */

static int jcs_emit_string(struct jcs_buffer *out, const char *s)
{
    int rc = jcs_buffer_append_byte(out, '"');
    if (rc < 0) {
        return rc;
    }
    for (const uint8_t *p = (const uint8_t *)s; *p != '\0'; p++) {
        uint8_t c = *p;
        switch (c) {
        case '"':
            rc = jcs_buffer_append_str(out, "\\\"");
            break;
        case '\\':
            rc = jcs_buffer_append_str(out, "\\\\");
            break;
        case '\b':
            rc = jcs_buffer_append_str(out, "\\b");
            break;
        case '\f':
            rc = jcs_buffer_append_str(out, "\\f");
            break;
        case '\n':
            rc = jcs_buffer_append_str(out, "\\n");
            break;
        case '\r':
            rc = jcs_buffer_append_str(out, "\\r");
            break;
        case '\t':
            rc = jcs_buffer_append_str(out, "\\t");
            break;
        default:
            if (c < 0x20) {
                char buf[7];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                rc = jcs_buffer_append_str(out, buf);
            } else {
                rc = jcs_buffer_append_byte(out, c);
            }
            break;
        }
        if (rc < 0) {
            return rc;
        }
    }
    return jcs_buffer_append_byte(out, '"');
}

/* ------------------------------------------------------------------ */
/* Comma + sortedness pre-check.                                      */
/*                                                                    */
/* Called from key() to insert "," between pairs and assert that the  */
/* arriving key is strictly greater than the previous one in this     */
/* scope. Empty initial prev_key is lexicographically less than any   */
/* non-empty key, so the first key always passes.                     */
/* ------------------------------------------------------------------ */

static int jcs_pre_key(struct jcs_canonical_ctx *ctx, const char *key)
{
    if (ctx->depth <= 0) {
        return -1;
    }
    struct jcs_scope *s = &ctx->scopes[ctx->depth - 1];
    if (!s->first) {
        int rc = jcs_buffer_append_byte(ctx->out, ',');
        if (rc < 0) {
            return rc;
        }
        if (strcmp(key, s->prev_key) <= 0) {
            /*
             * Out-of-order or duplicate key. Print the violating pair to
             * stderr — surfaces the bug at adapter-author dev time rather
             * than producing silently-wrong canonical bytes.
             */
            fprintf(stderr,
                    "jcs: keys not in sorted order: \"%s\" follows \"%s\"\n",
                    key, s->prev_key);
            return -1;
        }
    }
    s->first = false;
    /*
     * Truncate to fit prev_key buffer. Keys longer than 127 chars would
     * silently compare as their truncation; intentional cap, not a real
     * concern given v1 schema names are short.
     */
    strncpy(s->prev_key, key, sizeof(s->prev_key) - 1);
    s->prev_key[sizeof(s->prev_key) - 1] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* Ops.                                                               */
/* ------------------------------------------------------------------ */

static int jcs_op_object_open(void *raw)
{
    struct jcs_canonical_ctx *ctx = raw;
    if (ctx->depth >= JCS_MAX_DEPTH) {
        return -1;
    }
    ctx->scopes[ctx->depth].first = true;
    ctx->scopes[ctx->depth].prev_key[0] = '\0';
    ctx->depth++;
    return jcs_buffer_append_byte(ctx->out, '{');
}

static int jcs_op_object_close(void *raw)
{
    struct jcs_canonical_ctx *ctx = raw;
    if (ctx->depth <= 0) {
        return -1;
    }
    ctx->depth--;
    return jcs_buffer_append_byte(ctx->out, '}');
}

static int jcs_op_key(void *raw, const char *key)
{
    struct jcs_canonical_ctx *ctx = raw;
    int rc = jcs_pre_key(ctx, key);
    if (rc < 0) {
        return rc;
    }
    rc = jcs_emit_string(ctx->out, key);
    if (rc < 0) {
        return rc;
    }
    return jcs_buffer_append_byte(ctx->out, ':');
}

static int jcs_op_value_string(void *raw, const char *value)
{
    struct jcs_canonical_ctx *ctx = raw;
    return jcs_emit_string(ctx->out, value);
}

/*
 * uint64 → ASCII decimal. JCS / ECMAScript ToString is exact for integers in
 * [0, 2^53]; for larger values the spec mandates exponent form. v1 schema
 * never exceeds that, so we hard-fail above the safe integer ceiling rather
 * than silently produce non-canonical output.
 */
static int jcs_op_value_uint(void *raw, uint64_t value)
{
    struct jcs_canonical_ctx *ctx = raw;
    if (value > (((uint64_t)1) << 53)) {
        fprintf(stderr,
                "jcs: uint value %" PRIu64
                " exceeds 2^53 safe-integer ceiling\n",
                value);
        return -1;
    }
    char buf[24];
    int n = snprintf(buf, sizeof(buf), "%" PRIu64, value);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return -1;
    }
    return jcs_buffer_append(ctx->out, (const uint8_t *)buf, (size_t)n);
}

static int jcs_op_value_bytes_hex(void *raw, const uint8_t *bytes, size_t len)
{
    struct jcs_canonical_ctx *ctx = raw;
    static const char hex[] = "0123456789abcdef";
    int rc = jcs_buffer_append_byte(ctx->out, '"');
    if (rc < 0) {
        return rc;
    }
    for (size_t i = 0; i < len; i++) {
        uint8_t pair[2] = {(uint8_t)hex[bytes[i] >> 4],
                           (uint8_t)hex[bytes[i] & 0x0F]};
        rc = jcs_buffer_append(ctx->out, pair, 2);
        if (rc < 0) {
            return rc;
        }
    }
    return jcs_buffer_append_byte(ctx->out, '"');
}

static const struct attest_emitter_ops jcs_canonical_ops = {
    .object_open = jcs_op_object_open,
    .object_close = jcs_op_object_close,
    .key = jcs_op_key,
    .value_string = jcs_op_value_string,
    .value_uint = jcs_op_value_uint,
    .value_bytes_hex = jcs_op_value_bytes_hex,
};

void jcs_canonical_init(struct attest_emitter *em,
                        struct jcs_canonical_ctx *ctx,
                        struct jcs_buffer *out)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->out = out;
    em->ops = &jcs_canonical_ops;
    em->ctx = ctx;
}
