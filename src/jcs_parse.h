#pragma once

/*
 * JCS-canonical JSON parser — RFC 8785 subset, mirror of jcs.c emitter.
 *
 * Hand-rolled recursive-descent. Accepts only the canonical-output subset
 * the emitter produces:
 *   - objects, strings, unsigned integers (≤ 2^53)
 *   - no whitespace anywhere outside string values
 *   - object keys strictly increasing (UTF-8 byte order)
 *   - escapes restricted to \" \\ \b \f \n \r \t and \u00XX for control
 *     bytes 0x00-0x1F not covered by the named shortcuts
 *   - decimal integers only — no leading zero, no sign, no exponent
 *
 * Arrays are intentionally out of scope: nothing the v1 schema currently
 * emits uses them. They land alongside the modules.list adapter (session 7)
 * with both a parser and a canonical-emitter array op pair.
 *
 * Anything outside the accepted subset (whitespace, bare floats, ꯍ for
 * non-control codepoints, etc.) is rejected with -1. That strictness is the
 * point: a successful parse certifies the input is canonical, which is what
 * attest-diff relies on for byte-comparison shortcuts.
 *
 * Strings are stored as malloc'd, NUL-terminated buffers + an explicit
 * length. Embedded 0x00 bytes round-trip-safely on the length path but are
 * truncated when re-emitted via the canonical emitter (which takes NUL-
 * terminated strings) — v1 schema has no embedded NULs in any field.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    JCSP_STRING,
    JCSP_UINT,
    JCSP_OBJECT,
} jcsp_type_t;

/*
 * Forward declaration: jcsp_member references jcsp_value (by-value), and
 * jcsp_value's object members reference jcsp_member (by pointer). Pointers
 * tolerate incomplete types; values do not — so jcsp_value is defined
 * first, jcsp_member after.
 */
struct jcsp_member;

struct jcsp_value {
    jcsp_type_t type;
    union {
        struct {
            char *bytes;       /* malloc'd, NUL-terminated, unescaped */
            size_t len;        /* bytes excluding NUL */
        } string;
        uint64_t uint;
        struct {
            struct jcsp_member *members;
            size_t n;
        } object;
    } u;
};

struct jcsp_member {
    char *key;                 /* malloc'd, NUL-terminated */
    struct jcsp_value value;
};

/*
 * Parse JCS-canonical JSON. `bytes` need not be NUL-terminated. `out` must
 * point to caller-owned storage; on success the caller must eventually call
 * jcsp_value_free(out). On failure `out` is left in a freeable state too
 * (so callers can use a single cleanup path).
 *
 * Returns 0 on success, -1 on any deviation from canonical form or any I/O
 * shape error.
 */
int jcsp_parse(const uint8_t *bytes, size_t len, struct jcsp_value *out);

/*
 * Free everything jcsp_parse allocated under `v`, including v's own union
 * payload (but not v itself — callers stack-allocate v). Safe on a
 * default-zeroed value.
 */
void jcsp_value_free(struct jcsp_value *v);

/*
 * Re-emit `v` through the JCS canonical emitter into `out`. Round-trip
 * guarantee: if `bytes` was a successful jcsp_parse input, then re-emitting
 * the resulting tree yields byte-identical output (modulo embedded-NUL
 * truncation noted above).
 *
 * `out` must be jcs_buffer_init'd by the caller.
 */
struct jcs_buffer;
int jcsp_emit(const struct jcsp_value *v, struct jcs_buffer *out);

/*
 * Structural equality — same type, same content, recursively. Both inputs
 * must be canonical (sorted keys); equality is then a same-order traversal.
 */
bool jcsp_value_equals(const struct jcsp_value *a, const struct jcsp_value *b);

#ifdef __cplusplus
}
#endif
