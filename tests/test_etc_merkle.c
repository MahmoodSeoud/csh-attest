/*
 * etc.merkle adapter tests.
 *
 * Exercises compute_etc_merkle directly with synthetic file content under
 * a tmp directory. The production adapter (attest_adapter_etc_merkle) is
 * a thin wrapper with the v1 allowlist constant.
 *
 * Linux glibc/musl gate mkdtemp behind feature-test macros; meson.build
 * sets _GNU_SOURCE project-wide on Linux.
 */

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
#include <sodium.h>

#include "etc_merkle.h"

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

static char *make_tmpdir(void)
{
    char tmpl[] = "/tmp/csh-attest-merkle-XXXXXX";
    char *dir = mkdtemp(tmpl);
    assert_non_null(dir);
    return strdup(dir);
}

static void write_file(const char *dir, const char *name, const char *content)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    assert_non_null(f);
    if (content != NULL) {
        fputs(content, f);
    }
    fclose(f);
}

static void unlink_file(const char *dir, const char *name)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    unlink(path);
}

/* Format a hash as a hex string for diagnostic output. */
static void hex(char *out, const uint8_t *bytes, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    out[n * 2] = '\0';
}

/* ------------------------------------------------------------------ */
/* Tests.                                                             */
/* ------------------------------------------------------------------ */

static void test_empty_pathlist_is_sha256_of_empty(void **state)
{
    (void)state;
    /* No paths → root is SHA256(""). Compare against libsodium's reference. */
    uint8_t hash[ETC_MERKLE_HASH_BYTES];
    int rc = compute_etc_merkle(NULL, 0, hash);
    assert_int_equal(rc, 0);

    uint8_t expected[ETC_MERKLE_HASH_BYTES];
    crypto_hash_sha256(expected, NULL, 0);
    assert_memory_equal(hash, expected, sizeof(expected));
}

static void test_deterministic_for_same_inputs(void **state)
{
    (void)state;
    char *dir = make_tmpdir();
    write_file(dir, "a", "alpha");
    write_file(dir, "b", "beta");
    char path_a[1024], path_b[1024];
    snprintf(path_a, sizeof(path_a), "%s/a", dir);
    snprintf(path_b, sizeof(path_b), "%s/b", dir);

    const char *paths[] = {path_a, path_b};

    uint8_t h1[32], h2[32];
    assert_int_equal(compute_etc_merkle(paths, 2, h1), 0);
    assert_int_equal(compute_etc_merkle(paths, 2, h2), 0);
    assert_memory_equal(h1, h2, sizeof(h1));

    unlink_file(dir, "a");
    unlink_file(dir, "b");
    rmdir(dir);
    free(dir);
}

static void test_input_order_does_not_matter(void **state)
{
    (void)state;
    char *dir = make_tmpdir();
    write_file(dir, "a", "alpha");
    write_file(dir, "b", "beta");
    char path_a[1024], path_b[1024];
    snprintf(path_a, sizeof(path_a), "%s/a", dir);
    snprintf(path_b, sizeof(path_b), "%s/b", dir);

    const char *order1[] = {path_a, path_b};
    const char *order2[] = {path_b, path_a};

    uint8_t h1[32], h2[32];
    assert_int_equal(compute_etc_merkle(order1, 2, h1), 0);
    assert_int_equal(compute_etc_merkle(order2, 2, h2), 0);

    if (memcmp(h1, h2, sizeof(h1)) != 0) {
        char hex1[65], hex2[65];
        hex(hex1, h1, 32);
        hex(hex2, h2, 32);
        print_error("order1 hash: %s\n", hex1);
        print_error("order2 hash: %s\n", hex2);
    }
    assert_memory_equal(h1, h2, sizeof(h1));

    unlink_file(dir, "a");
    unlink_file(dir, "b");
    rmdir(dir);
    free(dir);
}

static void test_different_content_produces_different_root(void **state)
{
    (void)state;
    char *dir = make_tmpdir();
    char path_a[1024];
    snprintf(path_a, sizeof(path_a), "%s/a", dir);
    const char *paths[] = {path_a};

    write_file(dir, "a", "version1");
    uint8_t h1[32];
    assert_int_equal(compute_etc_merkle(paths, 1, h1), 0);

    write_file(dir, "a", "version2");
    uint8_t h2[32];
    assert_int_equal(compute_etc_merkle(paths, 1, h2), 0);

    /* Different content under the same path → different root. */
    assert_int_not_equal(memcmp(h1, h2, sizeof(h1)), 0);

    unlink_file(dir, "a");
    rmdir(dir);
    free(dir);
}

static void test_missing_file_treated_as_empty(void **state)
{
    (void)state;
    char *dir = make_tmpdir();

    char path_present[1024], path_missing[1024];
    snprintf(path_present, sizeof(path_present), "%s/present", dir);
    snprintf(path_missing, sizeof(path_missing), "%s/missing", dir);
    write_file(dir, "present", "alpha");
    /* Don't create "missing". */

    /* Also create an empty "missing" file in a different dir to compare. */
    char *dir2 = make_tmpdir();
    char path_empty[1024];
    snprintf(path_empty, sizeof(path_empty), "%s/missing", dir2);
    write_file(dir2, "missing", "");

    /*
     * Hashes computed against the SAME path string but with the file
     * absent vs empty must MATCH — that's the spec: missing == empty.
     * (We hash content_only, not file metadata, so missing/empty are
     * indistinguishable to compute_etc_merkle.)  We simulate this by
     * computing once with the file missing and once with it empty,
     * holding the path string identical.
     */
    const char *paths[] = {path_present, path_missing};
    uint8_t h_missing[32];
    assert_int_equal(compute_etc_merkle(paths, 2, h_missing), 0);

    write_file(dir, "missing", ""); /* now file exists, but is empty */
    uint8_t h_empty[32];
    assert_int_equal(compute_etc_merkle(paths, 2, h_empty), 0);

    assert_memory_equal(h_missing, h_empty, sizeof(h_missing));

    unlink_file(dir, "present");
    unlink_file(dir, "missing");
    rmdir(dir);
    free(dir);
    unlink_file(dir2, "missing");
    rmdir(dir2);
    free(dir2);
}

static void test_path_string_is_part_of_hash(void **state)
{
    (void)state;
    /*
     * Two files in different dirs, identical content. Different paths must
     * yield different roots — proves that path bytes are folded into the
     * outer hash, not just content.
     */
    char *dir1 = make_tmpdir();
    char *dir2 = make_tmpdir();
    write_file(dir1, "f", "same content");
    write_file(dir2, "f", "same content");

    char p1[1024], p2[1024];
    snprintf(p1, sizeof(p1), "%s/f", dir1);
    snprintf(p2, sizeof(p2), "%s/f", dir2);

    const char *paths1[] = {p1};
    const char *paths2[] = {p2};

    uint8_t h1[32], h2[32];
    assert_int_equal(compute_etc_merkle(paths1, 1, h1), 0);
    assert_int_equal(compute_etc_merkle(paths2, 1, h2), 0);
    assert_int_not_equal(memcmp(h1, h2, sizeof(h1)), 0);

    unlink_file(dir1, "f");
    unlink_file(dir2, "f");
    rmdir(dir1);
    rmdir(dir2);
    free(dir1);
    free(dir2);
}

static void test_known_value_single_file(void **state)
{
    (void)state;
    /*
     * Lock a known hash to detect accidental algorithm changes. Computed
     * by hand:
     *   path = "/tmp/csh-attest-merkle-fixed/f"
     *   content = "abc"
     * Algorithm:
     *   ph = SHA256(path)
     *   ch = SHA256("abc") (a well-known vector)
     *   root = SHA256(ph || ch)
     *
     * Rather than hardcode the hex (would tie the test to whichever path
     * tmpdir produced), we recompute the expected value here using
     * libsodium directly, then compare against compute_etc_merkle.  This
     * proves the implementation matches the documented algorithm
     * end-to-end.
     */
    char *dir = make_tmpdir();
    write_file(dir, "f", "abc");
    char path[1024];
    snprintf(path, sizeof(path), "%s/f", dir);
    const char *paths[] = {path};

    uint8_t got[32];
    assert_int_equal(compute_etc_merkle(paths, 1, got), 0);

    /* Recompute the spec output manually. */
    uint8_t ph[32];
    crypto_hash_sha256(ph, (const uint8_t *)path, strlen(path));
    uint8_t ch[32];
    crypto_hash_sha256(ch, (const uint8_t *)"abc", 3);
    uint8_t expected[32];
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, ph, 32);
    crypto_hash_sha256_update(&st, ch, 32);
    crypto_hash_sha256_final(&st, expected);

    assert_memory_equal(got, expected, sizeof(expected));

    unlink_file(dir, "f");
    rmdir(dir);
    free(dir);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_empty_pathlist_is_sha256_of_empty),
        cmocka_unit_test(test_deterministic_for_same_inputs),
        cmocka_unit_test(test_input_order_does_not_matter),
        cmocka_unit_test(test_different_content_produces_different_root),
        cmocka_unit_test(test_missing_file_treated_as_empty),
        cmocka_unit_test(test_path_string_is_part_of_hash),
        cmocka_unit_test(test_known_value_single_file),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
