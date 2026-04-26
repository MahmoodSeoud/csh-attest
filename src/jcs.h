#pragma once

/*
 * JSON Canonicalization Scheme (JCS) — RFC 8785.
 *
 * Implements the subset csh-attest's v1 schema needs:
 *   - Object key sorting (enforced via sortedness check, NOT via buffering;
 *     adapters MUST emit keys in sorted order, walker drives them in sorted
 *     order). Sort order is byte-wise — adequate while every v1 schema key
 *     is ASCII; becomes a UTF-16 conversion at the point a non-ASCII key is
 *     introduced.
 *   - String escapes per §3.2.2.2 (\" \\ \b \f \n \r \t \u00XX for control
 *     characters; UTF-8 bytes ≥ 0x80 pass through unchanged).
 *   - Integer serialization for uint64 values within the 2^53 safe-integer
 *     range. Larger values fail the call (no v1 schema field exceeds 2^53).
 *   - Lowercase hex byte serialization (no separators, double-quoted).
 *   - No whitespace anywhere in the output.
 *
 * Out of scope here (deferred):
 *   - Floating point ToString — no v1 field is float.
 *   - Array open/close — no v1 adapter needs arrays yet.
 *   - Reference test vector compliance suite (cyberphone) — fits next
 *     session alongside libsodium signing as "crypto interop".
 *
 * Streaming design: keys + values flow straight to the output buffer. A
 * small per-scope state tracks "have we emitted the first key" (for comma
 * placement) and "what was the previous key" (for sort enforcement). The
 * cyberphone reference implementation buffers + sorts; we shift that work
 * onto the adapter authors and validate at runtime. This avoids a malloc-
 * heavy implementation in firmware-target code.
 */

#include "attest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Growable byte buffer. Caller owns, must call jcs_buffer_free. */
struct jcs_buffer {
    uint8_t *data;
    size_t len;
    size_t cap;
};

void jcs_buffer_init(struct jcs_buffer *b);
void jcs_buffer_free(struct jcs_buffer *b);

/* Maximum object nesting depth. Conservative; the v1 schema is <= 2 deep. */
#define JCS_MAX_DEPTH 8

/*
 * Per-scope tracking. Stack-allocated by the caller as part of a wider ctx.
 * `prev_key` holds the most recently emitted key in this scope; the next
 * key() call must compare strictly greater. Initial empty string is the
 * lexicographic predecessor of any non-empty key, so the first key in a new
 * object always passes.
 */
struct jcs_scope {
    bool first;
    char prev_key[128];
};

struct jcs_canonical_ctx {
    struct jcs_buffer *out;
    int depth;
    struct jcs_scope scopes[JCS_MAX_DEPTH];
};

/*
 * Initialize an attest_emitter pinned to the canonical ops + the given ctx +
 * output buffer. The ctx and buffer must outlive `em`. Caller does not need
 * to memset the ctx — this function does it.
 */
void jcs_canonical_init(struct attest_emitter *em,
                        struct jcs_canonical_ctx *ctx,
                        struct jcs_buffer *out);

#ifdef __cplusplus
}
#endif
