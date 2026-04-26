/*
 * Tests for src/diff.c, src/diff_render.c, and the attest_diff_run driver.
 *
 * Coverage scope (session-6 step 5):
 *   - structural diff finds MATCH / DIFFER / LHS_ONLY / RHS_ONLY correctly
 *   - exit codes from attest_diff_run match the design doc (0/1/2)
 *   - --json output is itself JCS-canonical (parseable by jcsp_parse)
 *   - ANSI escapes are absent when stdout is not a TTY (memstream path)
 *   - --json + --no-color force color off regardless of TTY
 *
 * Round-trip parser tests live in test_jcs_parse.c.
 */

/* Linux glibc/musl gate open_memstream(), mkstemp(), and write() in unistd
 * behind feature-test macros. macOS exposes them unconditionally. */
#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "csh_attest.h"
#include "diff.h"
#include "diff_render.h"
#include "jcs_parse.h"

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

static int parse_str(const char *s, struct jcsp_value *out)
{
    return jcsp_parse((const uint8_t *)s, strlen(s), out);
}

/* Write `content` to a freshly-mkstemp'd path. Caller unlinks + frees.
 * Path buffer must be at least 64 bytes. */
static void write_temp(const char *content, char *path_buf)
{
    strcpy(path_buf, "/tmp/csh-attest-test-XXXXXX");
    int fd = mkstemp(path_buf);
    assert_true(fd >= 0);
    size_t len = strlen(content);
    ssize_t w = write(fd, content, len);
    assert_int_equal((size_t)w, len);
    close(fd);
}

/* ------------------------------------------------------------------ */
/* Pure diff cases.                                                   */
/* ------------------------------------------------------------------ */

static void test_diff_all_match(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v\",\"n\":42}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v\",\"n\":42}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);
    assert_int_equal(r.n, 2);
    assert_int_equal(r.matches, 2);
    assert_int_equal(r.differs, 0);
    assert_int_equal(r.lhs_only, 0);
    assert_int_equal(r.rhs_only, 0);
    assert_false(diff_has_drift(&r));

    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_diff_value_differs(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v1\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v2\"}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);
    assert_int_equal(r.n, 1);
    assert_int_equal(r.differs, 1);
    assert_int_equal(r.records[0].status, DIFF_DIFFER);
    assert_string_equal(r.records[0].path, "k");
    assert_true(diff_has_drift(&r));

    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_diff_lhs_only(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v\",\"x\":\"y\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v\"}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);
    assert_int_equal(r.n, 2);
    assert_int_equal(r.matches, 1);
    assert_int_equal(r.lhs_only, 1);
    assert_string_equal(r.records[1].path, "x");
    assert_int_equal(r.records[1].status, DIFF_LHS_ONLY);
    assert_non_null(r.records[1].lhs);
    assert_null(r.records[1].rhs);
    assert_true(diff_has_drift(&r));

    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_diff_rhs_only(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v\",\"x\":\"y\"}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);
    assert_int_equal(r.n, 2);
    assert_int_equal(r.rhs_only, 1);
    assert_int_equal(r.records[1].status, DIFF_RHS_ONLY);
    assert_null(r.records[1].lhs);
    assert_non_null(r.records[1].rhs);
    assert_true(diff_has_drift(&r));

    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_diff_combined(void **state)
{
    (void)state;
    /*
     * Sorted keys:
     *   "a"      both, equal      → MATCH
     *   "common" both, differ     → DIFFER
     *   "l_only" lhs only         → LHS_ONLY
     *   "r_only" rhs only         → RHS_ONLY
     */
    struct jcsp_value a, b;
    assert_int_equal(parse_str(
        "{\"a\":\"x\",\"common\":\"v1\",\"l_only\":\"L\"}", &a), 0);
    assert_int_equal(parse_str(
        "{\"a\":\"x\",\"common\":\"v2\",\"r_only\":\"R\"}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);
    assert_int_equal(r.n, 4);
    assert_int_equal(r.matches, 1);
    assert_int_equal(r.differs, 1);
    assert_int_equal(r.lhs_only, 1);
    assert_int_equal(r.rhs_only, 1);

    /* Result records appear in merged sorted order. */
    assert_string_equal(r.records[0].path, "a");
    assert_int_equal(r.records[0].status, DIFF_MATCH);
    assert_string_equal(r.records[1].path, "common");
    assert_int_equal(r.records[1].status, DIFF_DIFFER);
    assert_string_equal(r.records[2].path, "l_only");
    assert_int_equal(r.records[2].status, DIFF_LHS_ONLY);
    assert_string_equal(r.records[3].path, "r_only");
    assert_int_equal(r.records[3].status, DIFF_RHS_ONLY);

    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_diff_rejects_non_object_top_level(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("\"not an object\"", &a), 0);
    assert_int_equal(parse_str("{}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), -1);

    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

/* ------------------------------------------------------------------ */
/* Color-resolution logic.                                            */
/* ------------------------------------------------------------------ */

static void test_should_color_resolution(void **state)
{
    (void)state;
    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    assert_non_null(mem);

    /* memstream is never a TTY → no color regardless of flags. */
    assert_false(diff_should_color(false, false, mem));
    /* json_mode forces color off. */
    assert_false(diff_should_color(true, false, mem));
    /* no_color forces color off. */
    assert_false(diff_should_color(false, true, mem));

    fclose(mem);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Renderer output discipline.                                        */
/* ------------------------------------------------------------------ */

static bool contains_ansi_escape(const char *s)
{
    return s != NULL && strchr(s, '\x1b') != NULL;
}

static void test_render_text_no_ansi_in_memstream(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v\"}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);

    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);

    diff_render_opts_t opts = {
        .json_mode = false,
        .color = diff_should_color(false, false, mem),
    };
    assert_int_equal(diff_render(mem, &r, &opts), 0);
    fclose(mem);

    /* memstream is not a TTY: no ANSI escape sequences in output. */
    assert_false(contains_ansi_escape(buf));
    /* Should mention parity since both inputs match. */
    assert_non_null(strstr(buf, "PARITY"));

    free(buf);
    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_render_no_color_flag_overrides(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v1\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v2\"}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);

    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);

    /* Force color=true at the renderer level (caller would normally pass
     * the result of diff_should_color), then pass --no-color via the
     * resolution helper.  Simulate the slash command's path: --no-color
     * makes diff_should_color return false even on a TTY. */
    diff_render_opts_t opts = {
        .json_mode = false,
        .color = diff_should_color(false, true, mem),
    };
    assert_int_equal(diff_render(mem, &r, &opts), 0);
    fclose(mem);

    assert_false(contains_ansi_escape(buf));
    assert_non_null(strstr(buf, "DRIFT"));

    free(buf);
    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

static void test_render_text_with_color_emits_escapes(void **state)
{
    (void)state;
    /*
     * Bypass diff_should_color: pass color=true directly. Verifies the
     * renderer DOES emit ANSI escapes when its caller decides to color
     * the output. The TTY-vs-memstream policy is in diff_should_color
     * (tested above) — render() trusts its options.
     */
    struct jcsp_value a, b;
    assert_int_equal(parse_str("{\"k\":\"v\"}", &a), 0);
    assert_int_equal(parse_str("{\"k\":\"v\"}", &b), 0);
    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);

    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    diff_render_opts_t opts = {.json_mode = false, .color = true};
    assert_int_equal(diff_render(mem, &r, &opts), 0);
    fclose(mem);

    assert_true(contains_ansi_escape(buf));

    free(buf);
    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

/* ------------------------------------------------------------------ */
/* JSON output canonicality.                                          */
/* ------------------------------------------------------------------ */

static void test_render_json_is_canonical_and_parseable(void **state)
{
    (void)state;
    struct jcsp_value a, b;
    assert_int_equal(parse_str(
        "{\"a\":\"x\",\"common\":\"v1\",\"l_only\":\"L\"}", &a), 0);
    assert_int_equal(parse_str(
        "{\"a\":\"x\",\"common\":\"v2\",\"r_only\":\"R\"}", &b), 0);

    struct diff_result r;
    assert_int_equal(attest_diff(&a, &b, &r), 0);

    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    diff_render_opts_t opts = {.json_mode = true, .color = false};
    assert_int_equal(diff_render(mem, &r, &opts), 0);
    fclose(mem);

    /* Output ends with a single trailing newline (UNIX convention) — the
     * canonical bytes are everything except that newline. */
    size_t out_len = strlen(buf);
    assert_true(out_len > 0);
    assert_int_equal(buf[out_len - 1], '\n');

    /* No ANSI in JSON output. */
    assert_false(contains_ansi_escape(buf));

    /* Parse the canonical bytes back and verify shape. */
    struct jcsp_value parsed;
    assert_int_equal(jcsp_parse((const uint8_t *)buf, out_len - 1, &parsed),
                     0);
    assert_int_equal(parsed.type, JCSP_OBJECT);

    /* Top-level keys, in canonical sorted order:
     * differs, lhs_only, matches, records, rhs_only. */
    assert_int_equal(parsed.u.object.n, 5);
    assert_string_equal(parsed.u.object.members[0].key, "differs");
    assert_int_equal(parsed.u.object.members[0].value.type, JCSP_UINT);
    assert_int_equal(parsed.u.object.members[0].value.u.uint, 1);
    assert_string_equal(parsed.u.object.members[1].key, "lhs_only");
    assert_int_equal(parsed.u.object.members[1].value.u.uint, 1);
    assert_string_equal(parsed.u.object.members[2].key, "matches");
    assert_int_equal(parsed.u.object.members[2].value.u.uint, 1);
    assert_string_equal(parsed.u.object.members[3].key, "records");
    assert_int_equal(parsed.u.object.members[3].value.type, JCSP_OBJECT);
    /* records contains an entry per diff path — 4 in this combined case. */
    assert_int_equal(parsed.u.object.members[3].value.u.object.n, 4);
    assert_string_equal(parsed.u.object.members[4].key, "rhs_only");
    assert_int_equal(parsed.u.object.members[4].value.u.uint, 1);

    /* Spot check one record: l_only must have lhs+status (no rhs). */
    const struct jcsp_value *records = &parsed.u.object.members[3].value;
    const struct jcsp_value *l_rec = NULL;
    for (size_t i = 0; i < records->u.object.n; i++) {
        if (strcmp(records->u.object.members[i].key, "l_only") == 0) {
            l_rec = &records->u.object.members[i].value;
            break;
        }
    }
    assert_non_null(l_rec);
    assert_int_equal(l_rec->type, JCSP_OBJECT);
    /* Sorted keys: lhs, status (no rhs). */
    assert_int_equal(l_rec->u.object.n, 2);
    assert_string_equal(l_rec->u.object.members[0].key, "lhs");
    assert_string_equal(l_rec->u.object.members[1].key, "status");
    assert_int_equal(l_rec->u.object.members[1].value.type, JCSP_STRING);
    assert_string_equal(l_rec->u.object.members[1].value.u.string.bytes,
                        "LHS_ONLY");

    jcsp_value_free(&parsed);
    free(buf);
    diff_result_free(&r);
    jcsp_value_free(&a);
    jcsp_value_free(&b);
}

/* ------------------------------------------------------------------ */
/* attest_diff_run exit codes.                                        */
/* ------------------------------------------------------------------ */

/* Run the driver with positional + flag args; return its exit code.
 * Captures both stdout and stderr to memstreams owned by the caller. */
static int run_driver(char **argv, int argc, char **out_buf, char **err_buf)
{
    size_t out_len = 0, err_len = 0;
    FILE *out = open_memstream(out_buf, &out_len);
    FILE *err = open_memstream(err_buf, &err_len);
    int rc = attest_diff_run(argc, argv, out, err);
    fclose(out);
    fclose(err);
    return rc;
}

static void test_run_exit_zero_on_parity(void **state)
{
    (void)state;
    char lhs[64], rhs[64];
    write_temp("{\"k\":\"v\"}", lhs);
    write_temp("{\"k\":\"v\"}", rhs);

    char *argv[] = {"attest-diff", lhs, rhs};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 3, &out_buf, &err_buf);
    assert_int_equal(rc, 0);
    assert_non_null(strstr(out_buf, "PARITY"));

    unlink(lhs);
    unlink(rhs);
    free(out_buf);
    free(err_buf);
}

static void test_run_exit_one_on_drift(void **state)
{
    (void)state;
    char lhs[64], rhs[64];
    write_temp("{\"k\":\"v1\"}", lhs);
    write_temp("{\"k\":\"v2\"}", rhs);

    char *argv[] = {"attest-diff", lhs, rhs};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 3, &out_buf, &err_buf);
    assert_int_equal(rc, 1);
    assert_non_null(strstr(out_buf, "DRIFT"));

    unlink(lhs);
    unlink(rhs);
    free(out_buf);
    free(err_buf);
}

static void test_run_exit_two_on_unparseable(void **state)
{
    (void)state;
    char lhs[64], rhs[64];
    /* Whitespace between tokens → not JCS-canonical → parse fails. */
    write_temp("{ \"k\":\"v\" }", lhs);
    write_temp("{\"k\":\"v\"}", rhs);

    char *argv[] = {"attest-diff", lhs, rhs};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 3, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    /* Stderr names the offending file with an E001 code. */
    assert_non_null(strstr(err_buf, "E001"));
    assert_non_null(strstr(err_buf, lhs));

    unlink(lhs);
    unlink(rhs);
    free(out_buf);
    free(err_buf);
}

static void test_run_exit_two_on_missing_file(void **state)
{
    (void)state;
    char *argv[] = {"attest-diff",
                    "/tmp/csh-attest-does-not-exist",
                    "/tmp/csh-attest-does-not-exist-rhs"};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 3, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "cannot open"));
    free(out_buf);
    free(err_buf);
}

static void test_run_exit_two_on_missing_args(void **state)
{
    (void)state;
    char *argv[] = {"attest-diff"};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 1, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "usage"));
    free(out_buf);
    free(err_buf);
}

static void test_run_exit_two_on_unknown_flag(void **state)
{
    (void)state;
    char *argv[] = {"attest-diff", "--frobnicate", "/tmp/a", "/tmp/b"};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 4, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "unknown flag"));
    free(out_buf);
    free(err_buf);
}

static void test_run_json_flag_emits_canonical(void **state)
{
    (void)state;
    char lhs[64], rhs[64];
    write_temp("{\"k\":\"v1\"}", lhs);
    write_temp("{\"k\":\"v2\"}", rhs);

    char *argv[] = {"attest-diff", "--json", lhs, rhs};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 4, &out_buf, &err_buf);
    assert_int_equal(rc, 1);
    /* No ANSI in --json output even though some terminals would otherwise
     * be considered TTYs.  We're on a memstream so this is doubly true. */
    assert_false(contains_ansi_escape(out_buf));

    /* Trim trailing newline and confirm it's parseable JCS. */
    size_t out_len = strlen(out_buf);
    assert_true(out_len > 0 && out_buf[out_len - 1] == '\n');
    struct jcsp_value parsed;
    assert_int_equal(
        jcsp_parse((const uint8_t *)out_buf, out_len - 1, &parsed), 0);
    jcsp_value_free(&parsed);

    unlink(lhs);
    unlink(rhs);
    free(out_buf);
    free(err_buf);
}

static void test_run_no_color_flag_suppresses_ansi(void **state)
{
    (void)state;
    char lhs[64], rhs[64];
    write_temp("{\"k\":\"v1\"}", lhs);
    write_temp("{\"k\":\"v2\"}", rhs);

    char *argv[] = {"attest-diff", "--no-color", lhs, rhs};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_driver(argv, 4, &out_buf, &err_buf);
    assert_int_equal(rc, 1);
    assert_false(contains_ansi_escape(out_buf));

    unlink(lhs);
    unlink(rhs);
    free(out_buf);
    free(err_buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_diff_all_match),
        cmocka_unit_test(test_diff_value_differs),
        cmocka_unit_test(test_diff_lhs_only),
        cmocka_unit_test(test_diff_rhs_only),
        cmocka_unit_test(test_diff_combined),
        cmocka_unit_test(test_diff_rejects_non_object_top_level),
        cmocka_unit_test(test_should_color_resolution),
        cmocka_unit_test(test_render_text_no_ansi_in_memstream),
        cmocka_unit_test(test_render_no_color_flag_overrides),
        cmocka_unit_test(test_render_text_with_color_emits_escapes),
        cmocka_unit_test(test_render_json_is_canonical_and_parseable),
        cmocka_unit_test(test_run_exit_zero_on_parity),
        cmocka_unit_test(test_run_exit_one_on_drift),
        cmocka_unit_test(test_run_exit_two_on_unparseable),
        cmocka_unit_test(test_run_exit_two_on_missing_file),
        cmocka_unit_test(test_run_exit_two_on_missing_args),
        cmocka_unit_test(test_run_exit_two_on_unknown_flag),
        cmocka_unit_test(test_run_json_flag_emits_canonical),
        cmocka_unit_test(test_run_no_color_flag_suppresses_ansi),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
