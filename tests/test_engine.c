#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <cmocka.h>

#include "attest.h"

/*
 * Recording emitter — captures every call into the ops vtable so tests can
 * assert that the walker drove the adapter correctly. Stored as a
 * fixed-capacity ring of operation records; if a test exceeds capacity that
 * is itself a test failure (asserted in record_op).
 */

typedef enum {
    OP_OBJECT_OPEN,
    OP_OBJECT_CLOSE,
    OP_KEY,
    OP_VALUE_STRING,
} op_kind_t;

typedef struct {
    op_kind_t kind;
    char arg[128];
} op_record_t;

#define MAX_OPS 128

typedef struct {
    op_record_t ops[MAX_OPS];
    size_t count;
} recorder_t;

static int recorder_record(recorder_t *r, op_kind_t kind, const char *arg)
{
    assert_true(r->count < MAX_OPS);
    r->ops[r->count].kind = kind;
    if (arg) {
        strncpy(r->ops[r->count].arg, arg,
                sizeof(r->ops[r->count].arg) - 1);
        r->ops[r->count].arg[sizeof(r->ops[r->count].arg) - 1] = '\0';
    } else {
        r->ops[r->count].arg[0] = '\0';
    }
    r->count++;
    return 0;
}

static int rec_object_open(void *ctx) {
    return recorder_record(ctx, OP_OBJECT_OPEN, NULL);
}
static int rec_object_close(void *ctx) {
    return recorder_record(ctx, OP_OBJECT_CLOSE, NULL);
}
static int rec_key(void *ctx, const char *k) {
    return recorder_record(ctx, OP_KEY, k);
}
static int rec_value_string(void *ctx, const char *v) {
    return recorder_record(ctx, OP_VALUE_STRING, v);
}

static const struct attest_emitter_ops recorder_ops = {
    .object_open = rec_object_open,
    .object_close = rec_object_close,
    .key = rec_key,
    .value_string = rec_value_string,
};

static void recorder_attach(struct attest_emitter *em, recorder_t *r)
{
    em->ops = &recorder_ops;
    em->ctx = r;
}

/* ---------- Tests ---------- */

/*
 * The walker must produce: object_open as the first call, object_close as
 * the last, and somewhere in the middle a key("schema_version") + a
 * value_string("0.1.0") (since schema_version is now a regular table row
 * rather than a hard-coded envelope header). The exact position depends on
 * its JCS-sorted slot in the table.
 */
static void test_walker_emits_envelope(void **state)
{
    (void)state;

    recorder_t r = {0};
    struct attest_emitter em;
    recorder_attach(&em, &r);

    int rc = attest_emit(&em);
    assert_int_equal(rc, 0);

    assert_true(r.count >= 4);
    assert_int_equal(r.ops[0].kind, OP_OBJECT_OPEN);
    assert_int_equal(r.ops[r.count - 1].kind, OP_OBJECT_CLOSE);

    /* schema_version key must be followed immediately by its value. */
    bool found = false;
    for (size_t i = 0; i + 1 < r.count; i++) {
        if (r.ops[i].kind == OP_KEY &&
            strcmp(r.ops[i].arg, "schema_version") == 0 &&
            r.ops[i + 1].kind == OP_VALUE_STRING &&
            strcmp(r.ops[i + 1].arg, "0.1.0") == 0) {
            found = true;
            break;
        }
    }
    assert_true(found);
}

/*
 * The walker calls each row's emit_fn after emitting the row's key. Verify
 * that for each registered field we see a `key(<field-name>)` op somewhere
 * in the recording.
 */
static void test_walker_visits_each_field(void **state)
{
    (void)state;

    recorder_t r = {0};
    struct attest_emitter em;
    recorder_attach(&em, &r);

    int rc = attest_emit(&em);
    assert_int_equal(rc, 0);

    for (size_t i = 0; i < attest_fields_count; i++) {
        const char *expected = attest_fields[i].name;
        bool found = false;
        for (size_t j = 0; j < r.count; j++) {
            if (r.ops[j].kind == OP_KEY &&
                strcmp(r.ops[j].arg, expected) == 0) {
                found = true;
                break;
            }
        }
        /* On failure, print which key is missing then trip the assertion. */
        if (!found) {
            print_error("field key '%s' missing from emitter recording\n",
                        expected);
        }
        assert_true(found);
    }
}

/*
 * kernel.uname adapter, called directly. uname() works on Linux + macOS so
 * this is cross-platform. We do not assert specific values (those are
 * runtime-dependent) — only the structural shape: object_open, four
 * (key, value_string) pairs in alphabetical order, object_close.
 */
static void test_kernel_uname_adapter_shape(void **state)
{
    (void)state;

    recorder_t r = {0};
    struct attest_emitter em;
    recorder_attach(&em, &r);

    int rc = attest_adapter_kernel_uname(&em);
    assert_int_equal(rc, 0);

    /* Expected: 1 + 4*2 + 1 = 10 ops. */
    assert_int_equal(r.count, 10);
    assert_int_equal(r.ops[0].kind, OP_OBJECT_OPEN);
    assert_int_equal(r.ops[9].kind, OP_OBJECT_CLOSE);

    /* Alphabetical key order, matching JCS sort for free. */
    static const char *expected_keys[] = {
        "machine", "release", "sysname", "version",
    };
    for (size_t i = 0; i < 4; i++) {
        size_t key_idx = 1 + i * 2;
        size_t val_idx = key_idx + 1;
        assert_int_equal(r.ops[key_idx].kind, OP_KEY);
        assert_string_equal(r.ops[key_idx].arg, expected_keys[i]);
        assert_int_equal(r.ops[val_idx].kind, OP_VALUE_STRING);
        assert_true(r.ops[val_idx].arg[0] != '\0');
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_walker_emits_envelope),
        cmocka_unit_test(test_walker_visits_each_field),
        cmocka_unit_test(test_kernel_uname_adapter_shape),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
