/* Linux glibc/musl gate O_CLOEXEC behind _GNU_SOURCE. */
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

#include "sign.h"

/*
 * Per-test temp file path. Caller passes a stack buffer; suffix can be any
 * short tag for log readability. Files live under /tmp and are unlinked by
 * the test that created them.
 */
static void temp_path(char *out, size_t cap, const char *tag)
{
    snprintf(out, cap, "/tmp/csh-attest-test-%s-%d", tag, (int)getpid());
}

static void write_bytes(const char *path, const uint8_t *bytes, size_t len,
                        mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    assert_true(fd >= 0);
    ssize_t written = write(fd, bytes, len);
    assert_int_equal((size_t)written, len);
    close(fd);
}

/* ---------------------------------------------------------------- */

static void test_keypair_generates(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    /* libsodium embeds the pubkey in the second half of the secret key. */
    assert_memory_equal(pk, sk + 32, ATTEST_SIGN_PUBLIC_KEY_BYTES);
}

static void test_sign_verify_roundtrip(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    const char message[] =
        "{\"kernel.uname\":{\"machine\":\"x\"},\"schema_version\":\"0.1.0\"}";
    uint8_t sig[ATTEST_SIGN_SIGNATURE_BYTES];
    assert_int_equal(
        attest_sign_canonical((const uint8_t *)message, strlen(message), sk,
                              sig),
        ATTEST_SIGN_OK);
    assert_int_equal(
        attest_verify_canonical((const uint8_t *)message, strlen(message),
                                sig, pk),
        ATTEST_SIGN_OK);
}

static void test_verify_rejects_tampered_message(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    char message[] = "{\"k\":\"original\"}";
    uint8_t sig[ATTEST_SIGN_SIGNATURE_BYTES];
    assert_int_equal(
        attest_sign_canonical((const uint8_t *)message, strlen(message), sk,
                              sig),
        ATTEST_SIGN_OK);

    /* Tamper with the message after signing. */
    message[5] = 'X';
    assert_int_equal(
        attest_verify_canonical((const uint8_t *)message, strlen(message),
                                sig, pk),
        ATTEST_SIGN_ERR_VERIFY);
}

static void test_verify_rejects_tampered_signature(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    const char message[] = "{}";
    uint8_t sig[ATTEST_SIGN_SIGNATURE_BYTES];
    assert_int_equal(
        attest_sign_canonical((const uint8_t *)message, strlen(message), sk,
                              sig),
        ATTEST_SIGN_OK);

    sig[0] ^= 0xFF;
    assert_int_equal(
        attest_verify_canonical((const uint8_t *)message, strlen(message),
                                sig, pk),
        ATTEST_SIGN_ERR_VERIFY);
}

static void test_verify_rejects_wrong_key(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk_a[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk_a[ATTEST_SIGN_SECRET_KEY_BYTES];
    uint8_t pk_b[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk_b[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk_a, sk_a), ATTEST_SIGN_OK);
    assert_int_equal(attest_sign_keypair(pk_b, sk_b), ATTEST_SIGN_OK);

    const char message[] = "{}";
    uint8_t sig[ATTEST_SIGN_SIGNATURE_BYTES];
    assert_int_equal(
        attest_sign_canonical((const uint8_t *)message, strlen(message),
                              sk_a, sig),
        ATTEST_SIGN_OK);

    /* Verify with pk_b — different keypair, must fail. */
    assert_int_equal(
        attest_verify_canonical((const uint8_t *)message, strlen(message),
                                sig, pk_b),
        ATTEST_SIGN_ERR_VERIFY);
}

/* ---------------------------------------------------------------- */
/* File-loader perm checks.                                         */
/* ---------------------------------------------------------------- */

static void test_load_secret_key_rejects_world_readable(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    char path[256];
    temp_path(path, sizeof(path), "world-readable-sk");

    /* 0o644: world-readable, must be refused. */
    write_bytes(path, sk, sizeof(sk), 0644);

    uint8_t loaded[ATTEST_SIGN_SECRET_KEY_BYTES];
    int rc = attest_sign_load_secret_key(path, loaded);
    unlink(path);
    assert_int_equal(rc, ATTEST_SIGN_ERR_KEY_PERMS);
}

static void test_load_secret_key_rejects_group_readable(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    char path[256];
    temp_path(path, sizeof(path), "group-readable-sk");

    /* 0o640: owner read/write, group read, world none. Group bit alone
     * still violates strict-secrecy policy. */
    write_bytes(path, sk, sizeof(sk), 0640);

    uint8_t loaded[ATTEST_SIGN_SECRET_KEY_BYTES];
    int rc = attest_sign_load_secret_key(path, loaded);
    unlink(path);
    assert_int_equal(rc, ATTEST_SIGN_ERR_KEY_PERMS);
}

static void test_load_secret_key_accepts_owner_only(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    char path[256];
    temp_path(path, sizeof(path), "owner-only-sk");

    write_bytes(path, sk, sizeof(sk), 0600);

    uint8_t loaded[ATTEST_SIGN_SECRET_KEY_BYTES];
    int rc = attest_sign_load_secret_key(path, loaded);
    unlink(path);
    assert_int_equal(rc, ATTEST_SIGN_OK);
    assert_memory_equal(sk, loaded, sizeof(sk));
}

static void test_load_public_key_ignores_perms(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk, sk), ATTEST_SIGN_OK);

    char path[256];
    temp_path(path, sizeof(path), "world-readable-pk");

    /* 0o644: world-readable, perfectly fine for a public key. */
    write_bytes(path, pk, sizeof(pk), 0644);

    uint8_t loaded[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    int rc = attest_sign_load_public_key(path, loaded);
    unlink(path);
    assert_int_equal(rc, ATTEST_SIGN_OK);
    assert_memory_equal(pk, loaded, sizeof(pk));
}

static void test_load_secret_key_rejects_truncated_file(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    char path[256];
    temp_path(path, sizeof(path), "truncated-sk");

    /* 32 bytes — half a secret key. Must fail with KEY_FORMAT. */
    uint8_t bytes[32] = {0};
    write_bytes(path, bytes, sizeof(bytes), 0600);

    uint8_t loaded[ATTEST_SIGN_SECRET_KEY_BYTES];
    int rc = attest_sign_load_secret_key(path, loaded);
    unlink(path);
    assert_int_equal(rc, ATTEST_SIGN_ERR_KEY_FORMAT);
}

static void test_load_secret_key_rejects_oversized_file(void **state)
{
    (void)state;
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);

    char path[256];
    temp_path(path, sizeof(path), "oversized-sk");

    /* 65 bytes — one byte too many. Must fail with KEY_FORMAT. */
    uint8_t bytes[ATTEST_SIGN_SECRET_KEY_BYTES + 1] = {0};
    write_bytes(path, bytes, sizeof(bytes), 0600);

    uint8_t loaded[ATTEST_SIGN_SECRET_KEY_BYTES];
    int rc = attest_sign_load_secret_key(path, loaded);
    unlink(path);
    assert_int_equal(rc, ATTEST_SIGN_ERR_KEY_FORMAT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_keypair_generates),
        cmocka_unit_test(test_sign_verify_roundtrip),
        cmocka_unit_test(test_verify_rejects_tampered_message),
        cmocka_unit_test(test_verify_rejects_tampered_signature),
        cmocka_unit_test(test_verify_rejects_wrong_key),
        cmocka_unit_test(test_load_secret_key_rejects_world_readable),
        cmocka_unit_test(test_load_secret_key_rejects_group_readable),
        cmocka_unit_test(test_load_secret_key_accepts_owner_only),
        cmocka_unit_test(test_load_public_key_ignores_perms),
        cmocka_unit_test(test_load_secret_key_rejects_truncated_file),
        cmocka_unit_test(test_load_secret_key_rejects_oversized_file),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
