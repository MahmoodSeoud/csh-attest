/*
 * modules.list adapter tests.
 *
 * Exercise the testable helper directly with synthetic input:
 *   - fmemopen for the /proc/modules stream
 *   - a tmp directory pretending to be /sys/module, with srcversion files
 *
 * That keeps every test deterministic and platform-portable. The real-
 * production adapter (attest_adapter_modules_list) just wraps fopen +
 * "/sys/module" around this helper.
 *
 * Linux glibc/musl gate fmemopen, mkdtemp etc. behind feature-test macros;
 * meson.build sets _GNU_SOURCE project-wide on Linux.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

#include "attest.h"
#include "jcs.h"
#include "modules_list.h"

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

/* Make a temp dir and write `<dir>/<name>/srcversion` for each row in
 * the (name, srcversion) array. Returns malloc'd path; caller frees. */
static char *make_sysfs_root(const char *const *names,
                             const char *const *srcversions,
                             size_t n)
{
    char tmpl[] = "/tmp/csh-attest-modlist-XXXXXX";
    char *dir = mkdtemp(tmpl);
    assert_non_null(dir);
    char *root = strdup(dir);

    for (size_t i = 0; i < n; i++) {
        char modpath[1024];
        snprintf(modpath, sizeof(modpath), "%s/%s", root, names[i]);
        assert_int_equal(mkdir(modpath, 0700), 0);

        if (srcversions[i] != NULL) {
            /* GCC -Wformat-truncation analysis: filepath must exceed
             * sizeof(modpath) + len("/srcversion") + 1.  2048 covers it. */
            char filepath[2048];
            snprintf(filepath, sizeof(filepath), "%s/srcversion", modpath);
            FILE *f = fopen(filepath, "w");
            assert_non_null(f);
            /* Real srcversion files end with "\n"; replicate. */
            fprintf(f, "%s\n", srcversions[i]);
            fclose(f);
        }
    }
    return root;
}

/* Recursively rm a directory tree we just made. Bounded to our own /tmp
 * subtree, opens then unlinks one level deep — enough for the test
 * fixture shape (root/<modname>/srcversion). */
static void cleanup_sysfs_root(const char *root, const char *const *names,
                               size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s/srcversion", root, names[i]);
        unlink(filepath); /* may not exist — ignore */
        char modpath[1024];
        snprintf(modpath, sizeof(modpath), "%s/%s", root, names[i]);
        rmdir(modpath);
    }
    rmdir(root);
}

/* Run the helper against the given /proc/modules text + sysfs root,
 * return the canonical bytes (caller frees). */
static char *run_helper(const char *proc_modules_text, const char *sysfs_root,
                        size_t *out_len)
{
    FILE *stream = fmemopen((void *)proc_modules_text,
                            strlen(proc_modules_text), "r");
    assert_non_null(stream);

    struct jcs_buffer buf;
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_buffer_init(&buf);
    jcs_canonical_init(&em, &ctx, &buf);

    int rc = emit_modules_list_from_stream(stream, sysfs_root, &em);
    fclose(stream);
    assert_int_equal(rc, 0);

    /* Transfer ownership of buf.data — null-terminate via append_nul. */
    assert_int_equal(jcs_buffer_append_nul(&buf), 0);
    *out_len = buf.len;
    return (char *)buf.data;
}

/* ------------------------------------------------------------------ */
/* Tests.                                                             */
/* ------------------------------------------------------------------ */

static void test_empty_proc_modules(void **state)
{
    (void)state;
    /*
     * No modules. We pass a single newline rather than the empty string
     * because fmemopen() with size=0 is implementation-defined: glibc
     * returns a valid empty stream, macOS returns NULL. The helper skips
     * blank lines either way.
     */
    size_t len;
    char *out = run_helper("\n", "/nonexistent", &len);
    assert_string_equal(out, "[]");
    free(out);
}

static void test_single_module_with_srcversion(void **state)
{
    (void)state;
    const char *names[] = {"ext4"};
    const char *srcs[]  = {"abcd1234"};
    char *root = make_sysfs_root(names, srcs, 1);

    size_t len;
    char *out = run_helper("ext4 745472 1 - Live 0xffffffffc0123000\n",
                           root, &len);
    assert_string_equal(out, "[{\"name\":\"ext4\",\"srcversion\":\"abcd1234\"}]");
    free(out);
    cleanup_sysfs_root(root, names, 1);
    free(root);
}

static void test_multiple_modules_sorted(void **state)
{
    (void)state;
    /* Input order: vfat, ext4, btrfs.  Output must be alphabetically sorted. */
    const char *names[] = {"vfat", "ext4", "btrfs"};
    const char *srcs[]  = {"vsv", "esv", "bsv"};
    char *root = make_sysfs_root(names, srcs, 3);

    size_t len;
    char *out = run_helper(
        "vfat 50000 1 - Live 0x00\n"
        "ext4 745472 1 - Live 0x00\n"
        "btrfs 800000 0 - Live 0x00\n",
        root, &len);

    /* btrfs < ext4 < vfat alphabetically; "name" < "srcversion" within each. */
    assert_string_equal(
        out,
        "[{\"name\":\"btrfs\",\"srcversion\":\"bsv\"},"
        "{\"name\":\"ext4\",\"srcversion\":\"esv\"},"
        "{\"name\":\"vfat\",\"srcversion\":\"vsv\"}]");
    free(out);
    cleanup_sysfs_root(root, names, 3);
    free(root);
}

static void test_missing_srcversion_emits_empty_string(void **state)
{
    (void)state;
    /* Module has no srcversion file (built-in kmod). Helper emits "". */
    const char *names[] = {"builtin"};
    const char *srcs[]  = {NULL}; /* signal: don't write srcversion file */
    char *root = make_sysfs_root(names, srcs, 1);

    size_t len;
    char *out = run_helper("builtin 1024 0 - Live 0x00\n", root, &len);
    assert_string_equal(out, "[{\"name\":\"builtin\",\"srcversion\":\"\"}]");
    free(out);
    cleanup_sysfs_root(root, names, 1);
    free(root);
}

static void test_srcversion_trailing_whitespace_trimmed(void **state)
{
    (void)state;
    /*
     * make_sysfs_root appends "\n" to every srcversion. The helper must
     * trim that — output value contains no \n.
     */
    const char *names[] = {"ext4"};
    const char *srcs[]  = {"hash_no_newline_in_output"};
    char *root = make_sysfs_root(names, srcs, 1);

    size_t len;
    char *out = run_helper("ext4 1 1 - Live 0x00\n", root, &len);
    assert_non_null(strstr(out, "\"srcversion\":\"hash_no_newline_in_output\""));
    /* No literal \n inside the canonical bytes — JCS would have escaped it. */
    assert_null(strstr(out, "\\n"));
    free(out);
    cleanup_sysfs_root(root, names, 1);
    free(root);
}

static void test_blank_lines_skipped(void **state)
{
    (void)state;
    const char *names[] = {"ext4"};
    const char *srcs[]  = {"esv"};
    char *root = make_sysfs_root(names, srcs, 1);

    size_t len;
    char *out = run_helper(
        "\n"
        "  \n"
        "ext4 745472 1 - Live 0x00\n"
        "\n",
        root, &len);
    assert_string_equal(out, "[{\"name\":\"ext4\",\"srcversion\":\"esv\"}]");
    free(out);
    cleanup_sysfs_root(root, names, 1);
    free(root);
}

static void test_leading_whitespace_tolerated(void **state)
{
    (void)state;
    const char *names[] = {"ext4"};
    const char *srcs[]  = {"esv"};
    char *root = make_sysfs_root(names, srcs, 1);

    size_t len;
    char *out = run_helper("  ext4 745472 1 - Live 0x00\n", root, &len);
    assert_string_equal(out, "[{\"name\":\"ext4\",\"srcversion\":\"esv\"}]");
    free(out);
    cleanup_sysfs_root(root, names, 1);
    free(root);
}

static void test_adapter_runs_on_any_platform(void **state)
{
    (void)state;
    /*
     * The adapter wrapper should at minimum produce a syntactically valid
     * empty array on macOS or any environment without /proc/modules. On
     * Linux it produces real content, but the shape must be canonical
     * either way.
     */
    struct jcs_buffer buf;
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_buffer_init(&buf);
    jcs_canonical_init(&em, &ctx, &buf);

    int rc = attest_adapter_modules_list(&em);
    assert_int_equal(rc, 0);
    assert_int_equal(jcs_buffer_append_nul(&buf), 0);

    /* Must start with '[' and end with ']' — syntactically a JCS array. */
    assert_true(buf.len >= 2);
    assert_int_equal(buf.data[0], '[');
    assert_int_equal(buf.data[buf.len - 1], ']');

    jcs_buffer_free(&buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_empty_proc_modules),
        cmocka_unit_test(test_single_module_with_srcversion),
        cmocka_unit_test(test_multiple_modules_sorted),
        cmocka_unit_test(test_missing_srcversion_emits_empty_string),
        cmocka_unit_test(test_srcversion_trailing_whitespace_trimmed),
        cmocka_unit_test(test_blank_lines_skipped),
        cmocka_unit_test(test_leading_whitespace_tolerated),
        cmocka_unit_test(test_adapter_runs_on_any_platform),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
