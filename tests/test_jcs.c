#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "attest.h"
#include "jcs.h"

/*
 * Compose a fresh canonical emitter targeting a buffer. Caller responsible
 * for calling jcs_buffer_free(buf).
 */
static void canon(struct attest_emitter *em, struct jcs_canonical_ctx *ctx,
                  struct jcs_buffer *buf)
{
    jcs_buffer_init(buf);
    jcs_canonical_init(em, ctx, buf);
}

/* Compare buffer contents to a NUL-terminated literal. */
static void assert_buffer_equals(struct jcs_buffer *b, const char *expected)
{
    size_t exp_len = strlen(expected);
    if (b->len != exp_len ||
        memcmp(b->data, expected, exp_len) != 0) {
        print_error("expected: \"%s\" (%zu bytes)\n", expected, exp_len);
        print_error("actual:   \"%.*s\" (%zu bytes)\n",
                    (int)b->len, (const char *)b->data, b->len);
        assert_true(false);
    }
}

/* ---------- Object scaffolding ---------- */

static void test_empty_object(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_buffer_equals(&buf, "{}");

    jcs_buffer_free(&buf);
}

static void test_single_string_field(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "schema_version"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "0.1.0"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);

    assert_buffer_equals(&buf, "{\"schema_version\":\"0.1.0\"}");
    jcs_buffer_free(&buf);
}

static void test_two_fields_in_sorted_order(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "alpha"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "a"), 0);
    assert_int_equal(em.ops->key(em.ctx, "beta"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "b"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);

    assert_buffer_equals(&buf, "{\"alpha\":\"a\",\"beta\":\"b\"}");
    jcs_buffer_free(&buf);
}

static void test_out_of_order_keys_rejected(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "beta"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "b"), 0);
    /* "alpha" < "beta": JCS violation, must fail. */
    assert_int_not_equal(em.ops->key(em.ctx, "alpha"), 0);

    jcs_buffer_free(&buf);
}

static void test_duplicate_key_rejected(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "key"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "v"), 0);
    /* Duplicate: keys must be strictly increasing, not just non-decreasing. */
    assert_int_not_equal(em.ops->key(em.ctx, "key"), 0);

    jcs_buffer_free(&buf);
}

static void test_nested_object(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* { "outer": { "inner": "v" } } */
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "outer"), 0);
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "inner"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "v"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);

    assert_buffer_equals(&buf, "{\"outer\":{\"inner\":\"v\"}}");
    jcs_buffer_free(&buf);
}

static void test_nested_object_resets_sort_state(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /*
     * Each scope's sort state is independent. After emitting an inner-scope
     * key "z", the next outer-scope key only has to beat the outer prev_key.
     */
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "a"), 0);
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "z"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "v"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    /* Outer "b" follows outer "a"; inner "z" must not have polluted state. */
    assert_int_equal(em.ops->key(em.ctx, "b"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "x"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);

    assert_buffer_equals(&buf, "{\"a\":{\"z\":\"v\"},\"b\":\"x\"}");
    jcs_buffer_free(&buf);
}

/* ---------- String escapes (RFC 8785 §3.2.2.2) ---------- */

static void test_string_escapes(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /*
     * Single-call value_string with: " \ \b \f \n \r \t and a control char
     * (0x01) plus a printable ASCII run. Verifies all the named-shortcut
     * escapes plus the \u00XX fallback.
     */
    const char input[] = "\"\\\b\f\n\r\t\x01plain";
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "k"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, input), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);

    assert_buffer_equals(
        &buf,
        "{\"k\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001plain\"}");
    jcs_buffer_free(&buf);
}

static void test_utf8_passthrough(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* UTF-8 bytes ≥ 0x80 must pass through unescaped. "Ω" is U+03A9 = CE A9. */
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "k"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "Ω"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);

    assert_buffer_equals(&buf, "{\"k\":\"\xCE\xA9\"}");
    jcs_buffer_free(&buf);
}

/* ---------- Numbers + bytes ---------- */

static void test_uint_serialization(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "zero"), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 0), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_buffer_equals(&buf, "{\"zero\":0}");
    jcs_buffer_free(&buf);

    canon(&em, &ctx, &buf);
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "n"), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 1234567890ULL), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_buffer_equals(&buf, "{\"n\":1234567890}");
    jcs_buffer_free(&buf);
}

static void test_uint_above_safe_integer_rejected(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "huge"), 0);
    /* 2^53 + 1 overflows ECMAScript safe-integer range. */
    uint64_t huge = (((uint64_t)1) << 53) + 1;
    assert_int_not_equal(em.ops->value_uint(em.ctx, huge), 0);

    jcs_buffer_free(&buf);
}

static void test_bytes_hex(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* Empty bytes → "" (just the wrapping quotes). */
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "k"), 0);
    const uint8_t empty_bytes[1] = {0};
    assert_int_equal(em.ops->value_bytes_hex(em.ctx, empty_bytes, 0), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_buffer_equals(&buf, "{\"k\":\"\"}");
    jcs_buffer_free(&buf);

    /* SHA-256 sized: 32 bytes → 64 lowercase hex chars. */
    canon(&em, &ctx, &buf);
    uint8_t bytes[32];
    for (size_t i = 0; i < sizeof(bytes); i++) {
        bytes[i] = (uint8_t)i;
    }
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "h"), 0);
    assert_int_equal(em.ops->value_bytes_hex(em.ctx, bytes, sizeof(bytes)), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_buffer_equals(
        &buf,
        "{\"h\":\"000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f\"}");
    jcs_buffer_free(&buf);
}

/* ---------- Arrays ---------- */

static void test_empty_array(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_buffer_equals(&buf, "[]");

    jcs_buffer_free(&buf);
}

static void test_array_with_strings(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* [ "a", "b", "c" ] — order is preserved verbatim. */
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "a"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "b"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "c"), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_buffer_equals(&buf, "[\"a\",\"b\",\"c\"]");

    jcs_buffer_free(&buf);
}

static void test_array_with_uints(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 0), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 42), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 9007199254740992ULL), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_buffer_equals(&buf, "[0,42,9007199254740992]");

    jcs_buffer_free(&buf);
}

static void test_array_of_objects(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* [ {"k":"v1"}, {"k":"v2"} ] — modules.list shape. */
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "k"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "v1"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "k"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "v2"), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_buffer_equals(&buf, "[{\"k\":\"v1\"},{\"k\":\"v2\"}]");

    jcs_buffer_free(&buf);
}

static void test_object_containing_array(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* { "modules": [ "ext4", "vfat" ] } */
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_equal(em.ops->key(em.ctx, "modules"), 0);
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "ext4"), 0);
    assert_int_equal(em.ops->value_string(em.ctx, "vfat"), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_int_equal(em.ops->object_close(em.ctx), 0);
    assert_buffer_equals(&buf, "{\"modules\":[\"ext4\",\"vfat\"]}");

    jcs_buffer_free(&buf);
}

static void test_nested_arrays(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* [[1,2],[3,4]] */
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 1), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 2), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 3), 0);
    assert_int_equal(em.ops->value_uint(em.ctx, 4), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_int_equal(em.ops->array_close(em.ctx), 0);
    assert_buffer_equals(&buf, "[[1,2],[3,4]]");

    jcs_buffer_free(&buf);
}

static void test_mismatched_bracket_rejected(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;

    /* Object-open then array-close → fails. */
    canon(&em, &ctx, &buf);
    assert_int_equal(em.ops->object_open(em.ctx), 0);
    assert_int_not_equal(em.ops->array_close(em.ctx), 0);
    jcs_buffer_free(&buf);

    /* Array-open then object-close → fails. */
    canon(&em, &ctx, &buf);
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_not_equal(em.ops->object_close(em.ctx), 0);
    jcs_buffer_free(&buf);
}

static void test_key_in_array_scope_rejected(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    /* key() is meaningless inside an array — must reject. */
    assert_int_equal(em.ops->array_open(em.ctx), 0);
    assert_int_not_equal(em.ops->key(em.ctx, "k"), 0);

    jcs_buffer_free(&buf);
}

/* ---------- Integration: attest_emit through canonical ---------- */

/*
 * Driving the full table walker through the canonical emitter produces
 * byte-stable output. We don't pin the exact uname values (runtime-
 * dependent) but the prefix up through the kernel.uname object_open is
 * deterministic, and the manifest must end with the schema_version pair.
 */
static void test_attest_emit_canonical_shape(void **state)
{
    (void)state;
    struct attest_emitter em;
    struct jcs_canonical_ctx ctx;
    struct jcs_buffer buf;
    canon(&em, &ctx, &buf);

    int rc = attest_emit(&em);
    assert_int_equal(rc, 0);

    /*
     * No whitespace between JCS tokens. Whitespace INSIDE string literals is
     * allowed (uname version strings contain spaces — they are part of the
     * payload). We scan only the structural bytes by tracking a simple "are
     * we currently inside a quoted string" flag, honoring \" escapes.
     */
    bool in_string = false;
    for (size_t i = 0; i < buf.len; i++) {
        uint8_t c = buf.data[i];
        if (c == '"' && (i == 0 || buf.data[i - 1] != '\\')) {
            in_string = !in_string;
            continue;
        }
        if (!in_string) {
            assert_true(c != ' ' && c != '\n' && c != '\r' && c != '\t');
        }
    }

    /* Manifest envelope. */
    assert_true(buf.len >= 2);
    assert_int_equal(buf.data[0], '{');
    assert_int_equal(buf.data[buf.len - 1], '}');

    /* schema_version pair appears verbatim. */
    const char needle[] = "\"schema_version\":\"0.1.0\"";
    bool found = false;
    if (buf.len >= sizeof(needle) - 1) {
        for (size_t i = 0; i + sizeof(needle) - 1 <= buf.len; i++) {
            if (memcmp(buf.data + i, needle, sizeof(needle) - 1) == 0) {
                found = true;
                break;
            }
        }
    }
    assert_true(found);

    jcs_buffer_free(&buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_empty_object),
        cmocka_unit_test(test_single_string_field),
        cmocka_unit_test(test_two_fields_in_sorted_order),
        cmocka_unit_test(test_out_of_order_keys_rejected),
        cmocka_unit_test(test_duplicate_key_rejected),
        cmocka_unit_test(test_nested_object),
        cmocka_unit_test(test_nested_object_resets_sort_state),
        cmocka_unit_test(test_string_escapes),
        cmocka_unit_test(test_utf8_passthrough),
        cmocka_unit_test(test_uint_serialization),
        cmocka_unit_test(test_uint_above_safe_integer_rejected),
        cmocka_unit_test(test_bytes_hex),
        cmocka_unit_test(test_empty_array),
        cmocka_unit_test(test_array_with_strings),
        cmocka_unit_test(test_array_with_uints),
        cmocka_unit_test(test_array_of_objects),
        cmocka_unit_test(test_object_containing_array),
        cmocka_unit_test(test_nested_arrays),
        cmocka_unit_test(test_mismatched_bracket_rejected),
        cmocka_unit_test(test_key_in_array_scope_rejected),
        cmocka_unit_test(test_attest_emit_canonical_shape),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
