/*
 * Tests for the attest_verify_run driver (csh_attest.c).
 *
 * Mirrors test_diff.c's memstream pattern: a helper writes a payload to a
 * tmp file, the driver reads it and emits to memstream-backed stdout/stderr,
 * the test asserts on exit code + stderr text.
 *
 * Coverage:
 *   - happy path: sign-then-verify with matching pubkey  → exit 0
 *   - tampered manifest field                            → exit 1 + E201
 *   - tampered signature byte                            → exit 1 + E201
 *   - wrong pubkey                                       → exit 1 + E201
 *   - missing pubkey file                                → exit 2 + E203
 *   - missing signed.json                                → exit 2 + E001
 *   - non-canonical signed.json                          → exit 2 + E001
 *   - envelope missing "manifest" / "sig"                → exit 2 + E001
 *   - bad arg count                                      → exit 2 + usage
 *
 * fcntl O_CLOEXEC, mkstemp, and write require _GNU_SOURCE on glibc/musl;
 * meson.build sets _GNU_SOURCE project-wide on Linux.
 */

#include <fcntl.h>
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

#include "csh_attest.h"
#include "jcs.h"
#include "jcs_parse.h"
#include "sign.h"

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

static void temp_path(char *out, size_t cap, const char *tag)
{
    snprintf(out, cap, "/tmp/csh-attest-verify-%s-%d", tag, (int)getpid());
}

static void write_file_bytes(const char *path, const uint8_t *bytes,
                             size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    assert_true(fd >= 0);
    ssize_t w = write(fd, bytes, len);
    assert_int_equal((size_t)w, len);
    close(fd);
}

/*
 * Build a JCS-canonical signed envelope:
 *   {"manifest":"<inner>","sig":"<hex>"}
 * Returns malloc'd bytes the caller frees. Mirrors the production --sign
 * code path so the test is exercising the same byte-level shape.
 */
static char *build_envelope(const char *inner_canonical,
                            const uint8_t *signature, size_t *out_len)
{
    struct jcs_buffer buf;
    jcs_buffer_init(&buf);
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_canonical_init(&em, &ctx, &buf);

    int rc = em.ops->object_open(em.ctx);
    assert_int_equal(rc, 0);
    rc = em.ops->key(em.ctx, "manifest");
    assert_int_equal(rc, 0);
    rc = em.ops->value_string(em.ctx, inner_canonical);
    assert_int_equal(rc, 0);
    rc = em.ops->key(em.ctx, "sig");
    assert_int_equal(rc, 0);
    rc = em.ops->value_bytes_hex(em.ctx, signature,
                                 ATTEST_SIGN_SIGNATURE_BYTES);
    assert_int_equal(rc, 0);
    rc = em.ops->object_close(em.ctx);
    assert_int_equal(rc, 0);

    char *out = malloc(buf.len + 1);
    assert_non_null(out);
    memcpy(out, buf.data, buf.len);
    out[buf.len] = '\0';
    *out_len = buf.len;
    jcs_buffer_free(&buf);
    return out;
}

/* Drives attest_verify_run with the supplied argv, captures stdout+stderr
 * into caller-owned heap buffers (caller frees). */
static int run_verify(int argc, char **argv, char **out_buf, char **err_buf)
{
    size_t out_len = 0, err_len = 0;
    FILE *out = open_memstream(out_buf, &out_len);
    FILE *err = open_memstream(err_buf, &err_len);
    int rc = attest_verify_run(argc, argv, out, err);
    fclose(out);
    fclose(err);
    return rc;
}

/* Make a usable pubkey + signed envelope on disk. Inner canonical bytes,
 * signature, and pubkey are returned for assertion-by-tampering. */
typedef struct {
    char pk_path[256];
    char signed_path[256];
    uint8_t pk[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk[ATTEST_SIGN_SECRET_KEY_BYTES];
    char *envelope_bytes;
    size_t envelope_len;
} fixture_t;

static void fixture_make(fixture_t *fx, const char *tag,
                         const char *inner_canonical)
{
    assert_int_equal(attest_sign_init(), ATTEST_SIGN_OK);
    assert_int_equal(attest_sign_keypair(fx->pk, fx->sk), ATTEST_SIGN_OK);

    /* Sign the canonical inner bytes — the same payload that the production
     * --sign path embeds inside the envelope's "manifest" string field. */
    uint8_t sig[ATTEST_SIGN_SIGNATURE_BYTES];
    assert_int_equal(
        attest_sign_canonical((const uint8_t *)inner_canonical,
                              strlen(inner_canonical), fx->sk, sig),
        ATTEST_SIGN_OK);

    fx->envelope_bytes = build_envelope(inner_canonical, sig,
                                        &fx->envelope_len);

    char pk_tag[64], sig_tag[64];
    snprintf(pk_tag, sizeof(pk_tag), "%s-pk", tag);
    snprintf(sig_tag, sizeof(sig_tag), "%s-sig", tag);
    temp_path(fx->pk_path, sizeof(fx->pk_path), pk_tag);
    temp_path(fx->signed_path, sizeof(fx->signed_path), sig_tag);

    write_file_bytes(fx->pk_path, fx->pk, sizeof(fx->pk), 0644);
    write_file_bytes(fx->signed_path, (const uint8_t *)fx->envelope_bytes,
                     fx->envelope_len, 0644);
}

static void fixture_cleanup(fixture_t *fx)
{
    unlink(fx->pk_path);
    unlink(fx->signed_path);
    free(fx->envelope_bytes);
}

/* ------------------------------------------------------------------ */
/* Tests.                                                             */
/* ------------------------------------------------------------------ */

static void test_verify_happy_path(void **state)
{
    (void)state;
    fixture_t fx;
    fixture_make(&fx, "happy", "{\"k\":\"v\"}");

    char *argv[] = {(char *)"attest --verify", fx.pk_path, fx.signed_path};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(3, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 0);
    /* Verify is silent on success. */
    assert_int_equal(strlen(out_buf), 0);
    assert_int_equal(strlen(err_buf), 0);

    free(out_buf);
    free(err_buf);
    fixture_cleanup(&fx);
}

static void test_verify_rejects_wrong_pubkey(void **state)
{
    (void)state;
    fixture_t fx;
    fixture_make(&fx, "wrongpk", "{\"k\":\"v\"}");

    /* Generate a SECOND keypair, drop its pubkey at fx.pk_path, leaving the
     * envelope (signed by fx.sk, the FIRST keypair) unchanged. */
    uint8_t pk2[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sk2[ATTEST_SIGN_SECRET_KEY_BYTES];
    assert_int_equal(attest_sign_keypair(pk2, sk2), ATTEST_SIGN_OK);
    write_file_bytes(fx.pk_path, pk2, sizeof(pk2), 0644);

    char *argv[] = {(char *)"attest --verify", fx.pk_path, fx.signed_path};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(3, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 1);
    assert_non_null(strstr(err_buf, "E201"));

    free(out_buf);
    free(err_buf);
    fixture_cleanup(&fx);
}

static void test_verify_rejects_tampered_signature(void **state)
{
    (void)state;
    fixture_t fx;
    fixture_make(&fx, "tampsig", "{\"k\":\"v\"}");

    /* Flip the first hex char of "sig" inside the on-disk envelope. The
     * pattern `","sig":"` appears exactly once in the canonical envelope. */
    char *needle = strstr(fx.envelope_bytes, "\"sig\":\"");
    assert_non_null(needle);
    char *first_hex = needle + strlen("\"sig\":\"");
    /* Lowercase hex per canonical emit; flipping '0' ↔ '1' or 'a' ↔ 'b'
     * always lands on a still-valid hex char so the parse layer doesn't
     * reject before signature verification has a chance to run. */
    *first_hex = (*first_hex == '0') ? '1' : '0';
    write_file_bytes(fx.signed_path, (const uint8_t *)fx.envelope_bytes,
                     fx.envelope_len, 0644);

    char *argv[] = {(char *)"attest --verify", fx.pk_path, fx.signed_path};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(3, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 1);
    assert_non_null(strstr(err_buf, "E201"));

    free(out_buf);
    free(err_buf);
    fixture_cleanup(&fx);
}

static void test_verify_rejects_missing_pubkey(void **state)
{
    (void)state;
    fixture_t fx;
    fixture_make(&fx, "nopk", "{\"k\":\"v\"}");
    unlink(fx.pk_path);

    char *argv[] = {(char *)"attest --verify", fx.pk_path, fx.signed_path};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(3, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "E203"));

    free(out_buf);
    free(err_buf);
    unlink(fx.signed_path);
    free(fx.envelope_bytes);
}

static void test_verify_rejects_missing_signed_file(void **state)
{
    (void)state;
    fixture_t fx;
    fixture_make(&fx, "nosig", "{\"k\":\"v\"}");
    unlink(fx.signed_path);

    char *argv[] = {(char *)"attest --verify", fx.pk_path, fx.signed_path};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(3, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "E001"));

    free(out_buf);
    free(err_buf);
    unlink(fx.pk_path);
    free(fx.envelope_bytes);
}

static void test_verify_rejects_non_canonical_envelope(void **state)
{
    (void)state;
    fixture_t fx;
    fixture_make(&fx, "noncanon", "{\"k\":\"v\"}");

    /* Pre-pend a stray space — JCS rejects whitespace before the opening
     * brace. The parser surfaces this as a generic E001 parse failure. */
    const char *bad = " {\"manifest\":\"x\",\"sig\":\"00\"}";
    write_file_bytes(fx.signed_path, (const uint8_t *)bad, strlen(bad), 0644);

    char *argv[] = {(char *)"attest --verify", fx.pk_path, fx.signed_path};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(3, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "E001"));

    free(out_buf);
    free(err_buf);
    fixture_cleanup(&fx);
}

static void test_verify_rejects_envelope_missing_manifest(void **state)
{
    (void)state;
    fixture_t fx;
    fixture_make(&fx, "noman", "{\"k\":\"v\"}");

    /* Canonical JSON, but only "sig" — no "manifest" field. */
    const char *bad = "{\"sig\":\"00\"}";
    write_file_bytes(fx.signed_path, (const uint8_t *)bad, strlen(bad), 0644);

    char *argv[] = {(char *)"attest --verify", fx.pk_path, fx.signed_path};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(3, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    /* Generic E001 — "missing or malformed manifest/sig fields". */
    assert_non_null(strstr(err_buf, "manifest"));

    free(out_buf);
    free(err_buf);
    fixture_cleanup(&fx);
}

static void test_verify_rejects_bad_arg_count(void **state)
{
    (void)state;
    /* Only the command label, no pubkey, no signed file. */
    char *argv[] = {(char *)"attest --verify"};
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_verify(1, argv, &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "usage"));

    free(out_buf);
    free(err_buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_verify_happy_path),
        cmocka_unit_test(test_verify_rejects_wrong_pubkey),
        cmocka_unit_test(test_verify_rejects_tampered_signature),
        cmocka_unit_test(test_verify_rejects_missing_pubkey),
        cmocka_unit_test(test_verify_rejects_missing_signed_file),
        cmocka_unit_test(test_verify_rejects_non_canonical_envelope),
        cmocka_unit_test(test_verify_rejects_envelope_missing_manifest),
        cmocka_unit_test(test_verify_rejects_bad_arg_count),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
