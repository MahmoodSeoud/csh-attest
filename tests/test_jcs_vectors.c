/*
 * Cross-language interop test (design doc 3B-A).
 *
 * Each vector is a canonical-form JSON file produced by the cyberphone
 * reference implementation. We parse with jcsp_parse, re-emit through
 * jcs.c's canonical emitter, and assert byte-identical output. A pass
 * proves our emitter+parser pair agrees with cyberphone's interpretation
 * of RFC 8785.
 *
 * See tests/jcs/vectors/README.md for vector inventory + the
 * documented UTF-16 sort limitation around weird.json.
 *
 * JCS_VECTORS_DIR is injected by meson at compile time so the test
 * binary can locate the vectors directory in the source tree.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "attest.h"
#include "jcs.h"
#include "jcs_parse.h"

#ifndef JCS_VECTORS_DIR
#error "JCS_VECTORS_DIR must be defined by the build system"
#endif

/* ------------------------------------------------------------------ */
/* File loader.                                                       */
/* ------------------------------------------------------------------ */

static uint8_t *load_vector(const char *name, size_t *out_len)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s", JCS_VECTORS_DIR, name);
    assert_true(n > 0 && (size_t)n < sizeof(path));

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        print_error("could not open %s\n", path);
        assert_non_null(f);
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    assert_true(sz > 0);

    uint8_t *buf = malloc((size_t)sz);
    assert_non_null(buf);
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    assert_int_equal(r, (size_t)sz);

    *out_len = (size_t)sz;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Round-trip harness — parse, re-emit, compare bytewise.             */
/* ------------------------------------------------------------------ */

static void assert_round_trips(const char *vector_name)
{
    size_t len;
    uint8_t *bytes = load_vector(vector_name, &len);

    struct jcsp_value parsed;
    int rc = jcsp_parse(bytes, len, &parsed);
    if (rc != 0) {
        print_error("parse failed for %s\n", vector_name);
        free(bytes);
        assert_int_equal(rc, 0);
    }

    struct jcs_buffer reemit;
    jcs_buffer_init(&reemit);
    rc = jcsp_emit(&parsed, &reemit);
    if (rc != 0) {
        print_error("emit failed for %s\n", vector_name);
        jcs_buffer_free(&reemit);
        jcsp_value_free(&parsed);
        free(bytes);
        assert_int_equal(rc, 0);
    }

    if (reemit.len != len || memcmp(reemit.data, bytes, len) != 0) {
        print_error("byte mismatch for %s\n", vector_name);
        print_error("  expected (%zu bytes): %.*s\n",
                    len, (int)len, (const char *)bytes);
        print_error("  got      (%zu bytes): %.*s\n",
                    reemit.len, (int)reemit.len, (const char *)reemit.data);
    }
    assert_int_equal(reemit.len, len);
    assert_memory_equal(reemit.data, bytes, len);

    jcs_buffer_free(&reemit);
    jcsp_value_free(&parsed);
    free(bytes);
}

/* ------------------------------------------------------------------ */
/* Tests.                                                             */
/* ------------------------------------------------------------------ */

static void test_french(void **state)
{
    (void)state;
    /* Object key sort with French diacritics. UTF-8 byte order matches
     * UTF-16 code-unit order for these BMP characters, so our strcmp-
     * based sortedness check accepts the canonical form. */
    assert_round_trips("french.json");
}

static void test_structures(void **state)
{
    (void)state;
    /* Nested objects, arrays of objects, uint values, "\n" as a key,
     * empty objects, empty string as a key. All-ASCII keys → byte
     * order matches UTF-16 order. */
    assert_round_trips("structures.json");
}

static void test_unicode(void **state)
{
    (void)state;
    /* Single-key object with a non-ASCII string value (Å / U+00C5).
     * UTF-8 bytes pass through both parser and emitter unchanged. */
    assert_round_trips("unicode.json");
}

static void test_weird_known_limitation(void **state)
{
    (void)state;
    /*
     * Documented limitation: weird.json mixes BMP and supplementary-
     * plane keys (😂 = U+1F602 surrogate pair vs U+FB33 BMP). Under
     * UTF-16 sort (RFC 8785 spec) high-surrogate D83D < FB33; under
     * UTF-8 byte sort the F0 lead byte > EF, inverting the order.
     *
     * csh-attest uses byte-wise sortedness (see jcs.h), so this canonical
     * form fails our parser's sortedness check. Asserting the failure
     * here pins the behavior — when v0.x adopts UTF-16 sort the
     * assertion will flip and this becomes a positive round-trip case.
     *
     * See tests/jcs/vectors/README.md for the full rationale.
     */
    size_t len;
    uint8_t *bytes = load_vector("weird.json", &len);

    struct jcsp_value parsed;
    int rc = jcsp_parse(bytes, len, &parsed);
    if (rc == 0) {
        /* If we ever flip to UTF-16 sort this branch fires — flip the
         * assertion and the limitation graduates to a positive test. */
        print_error("weird.json now parses cleanly — flip this test to "
                    "assert_round_trips and update the README.\n");
        jcsp_value_free(&parsed);
        free(bytes);
        fail();
    }
    assert_int_not_equal(rc, 0);

    free(bytes);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_french),
        cmocka_unit_test(test_structures),
        cmocka_unit_test(test_unicode),
        cmocka_unit_test(test_weird_known_limitation),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
