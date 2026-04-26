/*
 * JCS parser tests — round-trip, sortedness enforcement, escape decode,
 * uint bounds, structural equality. Mirrors the emitter's test_jcs.c so
 * any divergence between the two halves of the pipeline shows up here.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "attest.h"
#include "jcs.h"
#include "jcs_parse.h"

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

static int parse_str(const char *s, struct jcsp_value *out)
{
    return jcsp_parse((const uint8_t *)s, strlen(s), out);
}

/* Round-trip: parse `s`, emit, expect byte-identical output. */
static void assert_round_trips(const char *s)
{
    struct jcsp_value v;
    int rc = parse_str(s, &v);
    if (rc != 0) {
        print_error("parse failed: %s\n", s);
        assert_int_equal(rc, 0);
    }

    struct jcs_buffer out;
    jcs_buffer_init(&out);
    int emit_rc = jcsp_emit(&v, &out);
    if (emit_rc != 0) {
        print_error("emit failed for: %s\n", s);
        jcs_buffer_free(&out);
        jcsp_value_free(&v);
        assert_int_equal(emit_rc, 0);
    }

    size_t expected_len = strlen(s);
    if (out.len != expected_len ||
        memcmp(out.data, s, expected_len) != 0) {
        print_error("round-trip mismatch:\n");
        print_error("  input:  %s\n", s);
        print_error("  output: %.*s\n", (int)out.len, (const char *)out.data);
    }
    assert_int_equal(out.len, expected_len);
    assert_memory_equal(out.data, s, expected_len);

    jcs_buffer_free(&out);
    jcsp_value_free(&v);
}

static void assert_parse_fails(const char *s)
{
    struct jcsp_value v;
    int rc = parse_str(s, &v);
    if (rc == 0) {
        print_error("expected parse failure but succeeded: %s\n", s);
        jcsp_value_free(&v);
        assert_int_not_equal(rc, 0);
    }
}

/* ------------------------------------------------------------------ */
/* Round-trip cases.                                                  */
/* ------------------------------------------------------------------ */

static void test_round_trip_empty_object(void **state)
{
    (void)state;
    assert_round_trips("{}");
}

static void test_round_trip_single_string(void **state)
{
    (void)state;
    assert_round_trips("{\"schema_version\":\"0.1.0\"}");
}

static void test_round_trip_multi_keys_sorted(void **state)
{
    (void)state;
    assert_round_trips("{\"alpha\":\"a\",\"beta\":\"b\",\"gamma\":\"c\"}");
}

static void test_round_trip_nested_object(void **state)
{
    (void)state;
    assert_round_trips(
        "{\"kernel.uname\":{\"machine\":\"arm64\",\"release\":\"24.0.0\","
        "\"sysname\":\"Darwin\",\"version\":\"abc\"},"
        "\"schema_version\":\"0.1.0\"}");
}

static void test_round_trip_escape_named(void **state)
{
    (void)state;
    /* All seven named-shortcut escapes plus \u00XX fallback. */
    assert_round_trips(
        "{\"k\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001plain\"}");
}

static void test_round_trip_utf8(void **state)
{
    (void)state;
    /* Greek capital omega: U+03A9 = CE A9. Passes through both ways. */
    assert_round_trips("{\"k\":\"\xCE\xA9\"}");
}

static void test_round_trip_uints(void **state)
{
    (void)state;
    assert_round_trips("{\"n\":0}");
    assert_round_trips("{\"n\":42}");
    assert_round_trips("{\"n\":1234567890}");
    /* 2^53 exactly, the safe-integer ceiling. */
    assert_round_trips("{\"n\":9007199254740992}");
}

static void test_round_trip_signed_envelope_shape(void **state)
{
    (void)state;
    /*
     * Mirrors the actual `attest --sign` output schema. Inner manifest
     * shows up as a string (canonical bytes after JCS string-escape) — we
     * use a tiny inner here, just enough to exercise the wrap pattern.
     */
    assert_round_trips(
        "{\"manifest\":\"{\\\"schema_version\\\":\\\"0.1.0\\\"}\","
        "\"sig\":\"deadbeef\"}");
}

/* ------------------------------------------------------------------ */
/* Canonical-input rejection cases.                                   */
/* ------------------------------------------------------------------ */

static void test_reject_whitespace_between_tokens(void **state)
{
    (void)state;
    assert_parse_fails("{\"a\": \"b\"}");
    assert_parse_fails("{\"a\":\"b\" }");
    assert_parse_fails(" {\"a\":\"b\"}");
    assert_parse_fails("{\"a\":\"b\", \"c\":\"d\"}");
    assert_parse_fails("{\n\"a\":\"b\"\n}");
}

static void test_reject_unsorted_keys(void **state)
{
    (void)state;
    /* "beta" < "alpha" is false, but the parser sees beta then alpha. */
    assert_parse_fails("{\"beta\":\"b\",\"alpha\":\"a\"}");
}

static void test_reject_duplicate_keys(void **state)
{
    (void)state;
    assert_parse_fails("{\"a\":\"x\",\"a\":\"y\"}");
}

static void test_reject_leading_zero_uint(void **state)
{
    (void)state;
    assert_parse_fails("{\"n\":01}");
    assert_parse_fails("{\"n\":007}");
}

static void test_reject_uint_above_safe_integer(void **state)
{
    (void)state;
    /* 2^53 + 1 exceeds the safe-integer ceiling. */
    assert_parse_fails("{\"n\":9007199254740993}");
}

static void test_reject_signed_uint(void **state)
{
    (void)state;
    assert_parse_fails("{\"n\":-1}");
}

static void test_reject_float(void **state)
{
    (void)state;
    assert_parse_fails("{\"n\":1.5}");
    assert_parse_fails("{\"n\":1e3}");
}

static void test_reject_uppercase_hex_in_escape(void **state)
{
    (void)state;
    /* JCS emitter uses lowercase only — uppercase \u00XX is non-canonical. */
    assert_parse_fails("{\"k\":\"\\u001F\"}");
}

static void test_reject_redundant_escape(void **state)
{
    (void)state;
    /* RFC 8785 §3.2.2.2: \u00XX is mandatory ONLY for control bytes that
     * lack a named shortcut.  is non-canonical (must use \b). */
    assert_parse_fails("{\"k\":\"\\u0008\"}");
    /* Printable ASCII: must NOT be escaped. */
    assert_parse_fails("{\"k\":\"\\u0041\"}");
}

static void test_reject_raw_control_byte(void **state)
{
    (void)state;
    /* Bare 0x01 inside a string must fail; canonical form requires . */
    const uint8_t bad[] = {'{', '"', 'k', '"', ':', '"', 0x01, '"', '}'};
    struct jcsp_value v;
    int rc = jcsp_parse(bad, sizeof(bad), &v);
    if (rc == 0) {
        jcsp_value_free(&v);
    }
    assert_int_not_equal(rc, 0);
}

static void test_reject_trailing_bytes(void **state)
{
    (void)state;
    assert_parse_fails("{}garbage");
    assert_parse_fails("{}{}");
}

static void test_reject_unterminated_object(void **state)
{
    (void)state;
    assert_parse_fails("{\"a\":\"b\"");
    assert_parse_fails("{");
}

static void test_reject_unterminated_string(void **state)
{
    (void)state;
    assert_parse_fails("{\"a\":\"b}");
}

/* ------------------------------------------------------------------ */
/* Structural equality.                                               */
/* ------------------------------------------------------------------ */

static void test_equality_matches(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str(
        "{\"k\":\"v\",\"n\":42}", &a), 0);
    assert_int_equal(parse_str(
        "{\"k\":\"v\",\"n\":42}", &b), 0);
    assert_true(jcsp_value_equals(&a, &b));
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_equality_string_differs(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v1\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v2\"}", &b), 0);
    assert_false(jcsp_value_equals(&a, &b));
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_equality_type_differs(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"42\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":42}", &b), 0);
    assert_false(jcsp_value_equals(&a, &b));
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_equality_uint(void **state)
{
    (void)state;
    struct jcsp_value a, b, c;
    assert_int_equal(parse_str("{\"n\":7}", &a), 0);
    assert_int_equal(parse_str("{\"n\":7}", &b), 0);
    assert_int_equal(parse_str("{\"n\":8}", &c), 0);
    assert_true(jcsp_value_equals(&a, &b));
    assert_false(jcsp_value_equals(&a, &c));
    jcsp_value_free(&a);
    jcsp_value_free(&b);
    jcsp_value_free(&c);
}

static void test_equality_object_member_count(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"a\":\"x\"}", &a), 0);
    assert_int_equal(parse_str("{\"a\":\"x\",\"b\":\"y\"}", &b), 0);
    assert_false(jcsp_value_equals(&a, &b));
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

/* ------------------------------------------------------------------ */
/* Round-trip a real attest_emit manifest.                            */
/* ------------------------------------------------------------------ */

static void test_round_trip_attest_emit(void **state)
{
    (void)state;
    /*
     * Drive the real adapter table through the canonical emitter, parse
     * the result, re-emit, expect byte-identical output. This is the
     * end-to-end interop check between emitter and parser.
     */
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    struct jcs_buffer manifest;
    jcs_buffer_init(&manifest);
    jcs_canonical_init(&em, &ctx, &manifest);
    assert_int_equal(attest_emit(&em), 0);

    struct jcsp_value parsed;
    assert_int_equal(jcsp_parse(manifest.data, manifest.len, &parsed), 0);

    struct jcs_buffer reemitted;
    jcs_buffer_init(&reemitted);
    assert_int_equal(jcsp_emit(&parsed, &reemitted), 0);

    assert_int_equal(reemitted.len, manifest.len);
    assert_memory_equal(reemitted.data, manifest.data, manifest.len);

    jcs_buffer_free(&reemitted);
    jcsp_value_free(&parsed);
    jcs_buffer_free(&manifest);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_round_trip_empty_object),
        cmocka_unit_test(test_round_trip_single_string),
        cmocka_unit_test(test_round_trip_multi_keys_sorted),
        cmocka_unit_test(test_round_trip_nested_object),
        cmocka_unit_test(test_round_trip_escape_named),
        cmocka_unit_test(test_round_trip_utf8),
        cmocka_unit_test(test_round_trip_uints),
        cmocka_unit_test(test_round_trip_signed_envelope_shape),
        cmocka_unit_test(test_reject_whitespace_between_tokens),
        cmocka_unit_test(test_reject_unsorted_keys),
        cmocka_unit_test(test_reject_duplicate_keys),
        cmocka_unit_test(test_reject_leading_zero_uint),
        cmocka_unit_test(test_reject_uint_above_safe_integer),
        cmocka_unit_test(test_reject_signed_uint),
        cmocka_unit_test(test_reject_float),
        cmocka_unit_test(test_reject_uppercase_hex_in_escape),
        cmocka_unit_test(test_reject_redundant_escape),
        cmocka_unit_test(test_reject_raw_control_byte),
        cmocka_unit_test(test_reject_trailing_bytes),
        cmocka_unit_test(test_reject_unterminated_object),
        cmocka_unit_test(test_reject_unterminated_string),
        cmocka_unit_test(test_equality_matches),
        cmocka_unit_test(test_equality_string_differs),
        cmocka_unit_test(test_equality_type_differs),
        cmocka_unit_test(test_equality_uint),
        cmocka_unit_test(test_equality_object_member_count),
        cmocka_unit_test(test_round_trip_attest_emit),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
