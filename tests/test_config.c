/*
 * Tests for src/config.c — mission allowlist loader.
 *
 * Covers piece 2 of v0.5.0:
 *   - Path validation (Tier 2 rules: absolute, no .., reject /proc//sys//dev/)
 *   - Sort + dedup
 *   - Per-kind cap (E106) at 512 entries
 *   - Empty array (the v0.4.x-compatible default)
 *   - attest_config_load fall-through to Tier 1 (Tier 2 is stubbed)
 *
 * Tier 2 paths.allow parsing tests land in piece 6 alongside the parser.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "config.h"

/* ------------------------------------------------------------------ */
/* attest_config_validate_path                                         */
/* ------------------------------------------------------------------ */

static void test_validate_accepts_absolute_path(void **state)
{
    (void)state;
    assert_int_equal(attest_config_validate_path("/usr/bin/payload"),
                     ATTEST_CONFIG_OK);
    assert_int_equal(attest_config_validate_path("/etc/hostname"),
                     ATTEST_CONFIG_OK);
    assert_int_equal(attest_config_validate_path("/opt/mission/x"),
                     ATTEST_CONFIG_OK);
}

static void test_validate_rejects_relative_path(void **state)
{
    (void)state;
    assert_int_equal(attest_config_validate_path("usr/bin"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("./relative"),
                     ATTEST_CONFIG_E_PATH);
}

static void test_validate_rejects_dotdot(void **state)
{
    (void)state;
    /* Classic traversal patterns. */
    assert_int_equal(attest_config_validate_path("/usr/../etc/shadow"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/.."),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/../foo"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/foo/.."),
                     ATTEST_CONFIG_E_PATH);
    /* Boundary: filename containing literal ".." but not as a segment. */
    assert_int_equal(attest_config_validate_path("/usr/foo..bar"),
                     ATTEST_CONFIG_OK);
    assert_int_equal(attest_config_validate_path("/usr/...weird"),
                     ATTEST_CONFIG_OK);
}

static void test_validate_rejects_proc_sys_dev(void **state)
{
    (void)state;
    assert_int_equal(attest_config_validate_path("/proc/self/mem"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/sys/kernel/notes"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/dev/zero"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/proc"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/sys"),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path("/dev"),
                     ATTEST_CONFIG_E_PATH);
    /* Boundary: paths that START with a forbidden-prefix string but are
     * not actually inside that directory must be allowed. */
    assert_int_equal(attest_config_validate_path("/procuration"),
                     ATTEST_CONFIG_OK);
    assert_int_equal(attest_config_validate_path("/system/foo"),
                     ATTEST_CONFIG_OK);
}

static void test_validate_rejects_empty_or_null(void **state)
{
    (void)state;
    assert_int_equal(attest_config_validate_path(NULL),
                     ATTEST_CONFIG_E_PATH);
    assert_int_equal(attest_config_validate_path(""),
                     ATTEST_CONFIG_E_PATH);
}

/* ------------------------------------------------------------------ */
/* attest_config_path_list_from_array                                  */
/* ------------------------------------------------------------------ */

static void test_path_list_empty(void **state)
{
    (void)state;
    attest_path_list_t l = {0};
    const char *const paths[] = {NULL};
    int rc = attest_config_path_list_from_array(&l, paths, /*validate=*/0);
    assert_int_equal(rc, ATTEST_CONFIG_OK);
    assert_int_equal(l.n, 0);
    assert_null(l.paths);
}

static void test_path_list_null_input(void **state)
{
    (void)state;
    attest_path_list_t l = {0};
    int rc = attest_config_path_list_from_array(&l, NULL, /*validate=*/0);
    assert_int_equal(rc, ATTEST_CONFIG_OK);
    assert_int_equal(l.n, 0);
}

static void test_path_list_sort(void **state)
{
    (void)state;
    /* Input deliberately out of order. */
    const char *const paths[] = {
        "/usr/lib",
        "/etc/hostname",
        "/opt/payload",
        "/usr/bin",
        NULL,
    };
    attest_path_list_t l = {0};
    int rc = attest_config_path_list_from_array(&l, paths, /*validate=*/0);
    assert_int_equal(rc, ATTEST_CONFIG_OK);
    assert_int_equal(l.n, 4);
    assert_string_equal(l.paths[0], "/etc/hostname");
    assert_string_equal(l.paths[1], "/opt/payload");
    assert_string_equal(l.paths[2], "/usr/bin");
    assert_string_equal(l.paths[3], "/usr/lib");

    /* Free via the public API path. */
    attest_config_t cfg = {0};
    cfg.binaries = l;
    attest_config_free(&cfg);
}

static void test_path_list_dedup(void **state)
{
    (void)state;
    const char *const paths[] = {
        "/usr/bin",
        "/etc/hostname",
        "/usr/bin",  /* duplicate */
        "/usr/bin",  /* duplicate */
        "/etc/hostname", /* duplicate */
        NULL,
    };
    attest_path_list_t l = {0};
    int rc = attest_config_path_list_from_array(&l, paths, /*validate=*/0);
    assert_int_equal(rc, ATTEST_CONFIG_OK);
    assert_int_equal(l.n, 2);
    assert_string_equal(l.paths[0], "/etc/hostname");
    assert_string_equal(l.paths[1], "/usr/bin");

    attest_config_t cfg = {0};
    cfg.binaries = l;
    attest_config_free(&cfg);
}

static void test_path_list_validation_rejects_bad_path(void **state)
{
    (void)state;
    const char *const paths[] = {
        "/usr/bin",
        "/proc/self/mem",  /* forbidden prefix */
        NULL,
    };
    attest_path_list_t l = {0};
    int rc = attest_config_path_list_from_array(&l, paths, /*validate=*/1);
    assert_int_equal(rc, ATTEST_CONFIG_E_PATH);
    assert_int_equal(l.n, 0);
}

static void test_path_list_validation_off_accepts_everything(void **state)
{
    (void)state;
    /*
     * Tier 1 paths are NOT validated at load time (build-time-trusted).
     * This lets a mission engineer point Tier 1 at /proc/foo if they
     * really know what they're doing — Tier 2 (runtime config) is the
     * adversarial surface and IS validated.
     */
    const char *const paths[] = {
        "/proc/self/mem",
        NULL,
    };
    attest_path_list_t l = {0};
    int rc = attest_config_path_list_from_array(&l, paths, /*validate=*/0);
    assert_int_equal(rc, ATTEST_CONFIG_OK);
    assert_int_equal(l.n, 1);
    assert_string_equal(l.paths[0], "/proc/self/mem");

    attest_config_t cfg = {0};
    cfg.binaries = l;
    attest_config_free(&cfg);
}

static void test_path_list_cap_e106(void **state)
{
    (void)state;
    /*
     * Build a NULL-terminated array of 513 paths (one over the cap).
     * Synthesize unique entries so dedup doesn't collapse them.
     */
    enum { OVER = ATTEST_CONFIG_MAX_PATHS_PER_KIND + 1u };
    char **synth = calloc(OVER + 1, sizeof(char *));
    assert_non_null(synth);
    for (size_t i = 0; i < OVER; i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "/opt/m/path-%05zu", i);
        synth[i] = strdup(buf);
        assert_non_null(synth[i]);
    }
    synth[OVER] = NULL;

    attest_path_list_t l = {0};
    int rc = attest_config_path_list_from_array(
        &l, (const char *const *)synth, /*validate=*/0);
    assert_int_equal(rc, ATTEST_CONFIG_E106);
    assert_int_equal(l.n, 0);

    for (size_t i = 0; i < OVER; i++) {
        free(synth[i]);
    }
    free(synth);
}

static void test_path_list_at_cap_succeeds(void **state)
{
    (void)state;
    /* Exactly 512 — at the cap, must succeed. */
    enum { AT = ATTEST_CONFIG_MAX_PATHS_PER_KIND };
    char **synth = calloc(AT + 1, sizeof(char *));
    assert_non_null(synth);
    for (size_t i = 0; i < AT; i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "/opt/m/path-%05zu", i);
        synth[i] = strdup(buf);
        assert_non_null(synth[i]);
    }
    synth[AT] = NULL;

    attest_path_list_t l = {0};
    int rc = attest_config_path_list_from_array(
        &l, (const char *const *)synth, /*validate=*/0);
    assert_int_equal(rc, ATTEST_CONFIG_OK);
    assert_int_equal(l.n, AT);

    attest_config_t cfg = {0};
    cfg.binaries = l;
    attest_config_free(&cfg);

    for (size_t i = 0; i < AT; i++) {
        free(synth[i]);
    }
    free(synth);
}

/* ------------------------------------------------------------------ */
/* attest_config_load — Tier 1 fallthrough                             */
/* ------------------------------------------------------------------ */

static void test_config_load_tier1_only(void **state)
{
    (void)state;
    /*
     * Tier 2 stub always returns "no file present" → Tier 1 fallback.
     *
     * Test is agnostic to the meson-build options the maintainer ran:
     *   meson setup build                                  → empty Tier 1
     *   meson setup build -Dbinaries_paths=/usr/bin,/x     → 2-entry Tier 1
     *
     * Both must succeed and produce a sorted, deduplicated, capped list.
     * The contract checked here is: load returns OK, n is within cap,
     * paths are sorted byte-wise, paths_allow_path is NULL (no Tier 2).
     */
    attest_config_t cfg = {0};
    int rc = attest_config_load(&cfg);
    assert_int_equal(rc, ATTEST_CONFIG_OK);
    assert_true(cfg.binaries.n <= ATTEST_CONFIG_MAX_PATHS_PER_KIND);
    assert_true(cfg.files.n    <= ATTEST_CONFIG_MAX_PATHS_PER_KIND);
    for (size_t i = 1; i < cfg.binaries.n; i++) {
        assert_true(strcmp(cfg.binaries.paths[i - 1],
                           cfg.binaries.paths[i]) < 0);
    }
    for (size_t i = 1; i < cfg.files.n; i++) {
        assert_true(strcmp(cfg.files.paths[i - 1],
                           cfg.files.paths[i]) < 0);
    }
    assert_null(cfg.paths_allow_path);
    attest_config_free(&cfg);
}

static void test_config_free_on_zero_struct(void **state)
{
    (void)state;
    /* attest_config_free must be safe on a zero-init struct. */
    attest_config_t cfg = {0};
    attest_config_free(&cfg);
    /* And on NULL. */
    attest_config_free(NULL);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_validate_accepts_absolute_path),
        cmocka_unit_test(test_validate_rejects_relative_path),
        cmocka_unit_test(test_validate_rejects_dotdot),
        cmocka_unit_test(test_validate_rejects_proc_sys_dev),
        cmocka_unit_test(test_validate_rejects_empty_or_null),
        cmocka_unit_test(test_path_list_empty),
        cmocka_unit_test(test_path_list_null_input),
        cmocka_unit_test(test_path_list_sort),
        cmocka_unit_test(test_path_list_dedup),
        cmocka_unit_test(test_path_list_validation_rejects_bad_path),
        cmocka_unit_test(test_path_list_validation_off_accepts_everything),
        cmocka_unit_test(test_path_list_cap_e106),
        cmocka_unit_test(test_path_list_at_cap_succeeds),
        cmocka_unit_test(test_config_load_tier1_only),
        cmocka_unit_test(test_config_free_on_zero_struct),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
