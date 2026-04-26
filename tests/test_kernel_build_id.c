/*
 * kernel.build_id adapter tests.
 *
 * Two layers of coverage:
 *
 *   1. kernel_build_id_extract — exercises the ELF .notes walker against
 *      synthetic byte buffers. No file I/O here; tests are pure data.
 *
 *   2. kernel_build_id_emit_from_path — the full file-reading path through
 *      a recording emitter. Linux glibc/musl gates mkstemp behind feature-
 *      test macros; meson.build sets _GNU_SOURCE project-wide on Linux.
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

#include "attest.h"
#include "kernel_build_id.h"

/* ------------------------------------------------------------------ */
/* ELF note builder.                                                  */
/* ------------------------------------------------------------------ */

/*
 * Append one note to `buf` at offset `off`. Returns new offset. Caller
 * sizes `buf` generously — 256 B is enough for every test case here.
 */
static size_t append_note(uint8_t *buf, size_t off,
                          const char *name, uint32_t type,
                          const uint8_t *desc, uint32_t descsz)
{
    uint32_t namesz = (uint32_t)strlen(name) + 1u; /* include trailing NUL */
    memcpy(buf + off, &namesz, sizeof(namesz)); off += 4;
    memcpy(buf + off, &descsz, sizeof(descsz)); off += 4;
    memcpy(buf + off, &type,   sizeof(type));   off += 4;

    memcpy(buf + off, name, namesz);
    off += namesz;
    while (off & 3u) {
        buf[off++] = 0;
    }
    if (descsz > 0u) {
        memcpy(buf + off, desc, descsz);
    }
    off += descsz;
    while (off & 3u) {
        buf[off++] = 0;
    }
    return off;
}

/* ------------------------------------------------------------------ */
/* extract() tests.                                                   */
/* ------------------------------------------------------------------ */

static void test_extract_finds_gnu_build_id(void **state)
{
    (void)state;
    uint8_t buf[256];
    const uint8_t bid[20] = {
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    size_t end = append_note(buf, 0, "GNU", 3u, bid, sizeof(bid));

    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    assert_int_equal(kernel_build_id_extract(buf, end, got, &got_len), 0);
    assert_int_equal(got_len, sizeof(bid));
    assert_memory_equal(got, bid, sizeof(bid));
}

static void test_extract_skips_non_gnu_note(void **state)
{
    (void)state;
    uint8_t buf[256];
    /* Two notes: first is "Stapsdt" type 3 (collides on type but wrong
     * name), second is the real "GNU" build-id. The walker must skip the
     * decoy. */
    const uint8_t fake_desc[8] = {0xaa, 0xbb, 0xcc, 0xdd,
                                  0xee, 0xff, 0x00, 0x11};
    const uint8_t bid[20] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    };
    size_t off = 0;
    off = append_note(buf, off, "Decoy", 3u, fake_desc, sizeof(fake_desc));
    off = append_note(buf, off, "GNU",   3u, bid,       sizeof(bid));

    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    assert_int_equal(kernel_build_id_extract(buf, off, got, &got_len), 0);
    assert_int_equal(got_len, sizeof(bid));
    assert_memory_equal(got, bid, sizeof(bid));
}

static void test_extract_returns_minus_two_when_absent(void **state)
{
    (void)state;
    uint8_t buf[256];
    /* Only a non-GNU note present. */
    const uint8_t desc[4] = {1, 2, 3, 4};
    size_t end = append_note(buf, 0, "stapsdt", 3u, desc, sizeof(desc));

    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    assert_int_equal(kernel_build_id_extract(buf, end, got, &got_len), -2);
}

static void test_extract_returns_minus_two_on_empty(void **state)
{
    (void)state;
    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    assert_int_equal(kernel_build_id_extract(NULL, 0, got, &got_len), -2);
}

static void test_extract_rejects_truncated_header(void **state)
{
    (void)state;
    /*
     * 11 bytes — one byte short of a complete 12-byte note header.
     * kernel_build_id_extract returns -2 (no note found) rather than -1
     * because the walker bails before it can determine truncation. Either
     * is acceptable per the contract — what matters is that a malformed
     * input does not produce a "found" result.
     */
    uint8_t buf[11] = {0};
    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    int rc = kernel_build_id_extract(buf, sizeof(buf), got, &got_len);
    assert_int_not_equal(rc, 0);
}

static void test_extract_rejects_truncated_note_body(void **state)
{
    (void)state;
    /* Header advertises a 32-byte desc, but buffer is too short. */
    uint8_t buf[24] = {0};
    uint32_t namesz = 4, descsz = 32, type = 3;
    memcpy(buf + 0, &namesz, 4);
    memcpy(buf + 4, &descsz, 4);
    memcpy(buf + 8, &type, 4);
    memcpy(buf + 12, "GNU", 4);

    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    assert_int_equal(kernel_build_id_extract(buf, sizeof(buf), got, &got_len),
                     -1);
}

static void test_extract_rejects_oversized_descsz(void **state)
{
    (void)state;
    /* GNU note that claims a 33-byte build-id — past the cap. The note is
     * fully present in the buffer, so this isn't a truncation case; the
     * walker rejects on size policy alone. */
    uint8_t buf[64] = {0};
    uint32_t namesz = 4, descsz = KERNEL_BUILD_ID_MAX_BYTES + 1u, type = 3;
    memcpy(buf + 0, &namesz, 4);
    memcpy(buf + 4, &descsz, 4);
    memcpy(buf + 8, &type, 4);
    memcpy(buf + 12, "GNU", 4);
    /* 16..16+33 = 49 bytes for desc — fits in 64-byte buf. */

    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    assert_int_equal(kernel_build_id_extract(buf, sizeof(buf), got, &got_len),
                     -1);
}

static void test_extract_rejects_zero_descsz(void **state)
{
    (void)state;
    /* GNU note with no payload — useless and almost certainly malformed. */
    uint8_t buf[64];
    size_t end = append_note(buf, 0, "GNU", 3u, NULL, 0);

    uint8_t got[KERNEL_BUILD_ID_MAX_BYTES];
    size_t got_len = 0;
    assert_int_equal(kernel_build_id_extract(buf, end, got, &got_len), -1);
}

/* ------------------------------------------------------------------ */
/* emit_from_path tests — recorder emitter intercepts value_bytes_hex. */
/* ------------------------------------------------------------------ */

typedef struct {
    bool got_value;
    uint8_t buf[KERNEL_BUILD_ID_MAX_BYTES];
    size_t len;
} hex_recorder_t;

static int rec_object_open(void *ctx) { (void)ctx; return 0; }
static int rec_object_close(void *ctx) { (void)ctx; return 0; }
static int rec_array_open(void *ctx) { (void)ctx; return 0; }
static int rec_array_close(void *ctx) { (void)ctx; return 0; }
static int rec_key(void *ctx, const char *k) { (void)ctx; (void)k; return 0; }
static int rec_value_string(void *ctx, const char *v)
{
    (void)ctx; (void)v;
    return 0;
}
static int rec_value_uint(void *ctx, uint64_t v) { (void)ctx; (void)v; return 0; }
static int rec_value_bytes_hex(void *ctx, const uint8_t *bytes, size_t len)
{
    hex_recorder_t *r = ctx;
    r->got_value = true;
    if (len > sizeof(r->buf)) {
        return -1;
    }
    memcpy(r->buf, bytes, len);
    r->len = len;
    return 0;
}

static const struct attest_emitter_ops recorder_ops = {
    .object_open = rec_object_open,
    .object_close = rec_object_close,
    .array_open = rec_array_open,
    .array_close = rec_array_close,
    .key = rec_key,
    .value_string = rec_value_string,
    .value_uint = rec_value_uint,
    .value_bytes_hex = rec_value_bytes_hex,
};

/* Write a heap buffer to a tmp file; caller unlinks. */
static void write_temp_bytes(char *path_buf, const uint8_t *bytes, size_t len)
{
    strcpy(path_buf, "/tmp/csh-attest-buildid-XXXXXX");
    int fd = mkstemp(path_buf);
    assert_true(fd >= 0);
    if (len > 0) {
        ssize_t w = write(fd, bytes, len);
        assert_int_equal((size_t)w, len);
    }
    close(fd);
}

static void test_emit_from_path_with_real_note(void **state)
{
    (void)state;
    uint8_t notes[256];
    const uint8_t bid[20] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
        0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    };
    size_t end = append_note(notes, 0, "GNU", 3u, bid, sizeof(bid));

    char path[64];
    write_temp_bytes(path, notes, end);

    hex_recorder_t r = {0};
    struct attest_emitter em = {.ops = &recorder_ops, .ctx = &r};
    assert_int_equal(kernel_build_id_emit_from_path(&em, path), 0);
    assert_true(r.got_value);
    assert_int_equal(r.len, sizeof(bid));
    assert_memory_equal(r.buf, bid, sizeof(bid));

    unlink(path);
}

static void test_emit_from_path_missing_file_emits_empty(void **state)
{
    (void)state;
    /* Path that almost certainly does not exist. */
    const char *path = "/tmp/csh-attest-no-such-file-buildid";
    /* Best-effort cleanup in case a previous run created it. */
    unlink(path);

    hex_recorder_t r = {0};
    struct attest_emitter em = {.ops = &recorder_ops, .ctx = &r};
    assert_int_equal(kernel_build_id_emit_from_path(&em, path), 0);
    assert_true(r.got_value);
    assert_int_equal(r.len, 0);
}

static void test_emit_from_path_no_note_emits_empty(void **state)
{
    (void)state;
    /* Notes file with only a non-GNU note → no build-id present →
     * emit empty string (deterministic placeholder). */
    uint8_t notes[64];
    const uint8_t fake[4] = {0, 1, 2, 3};
    size_t end = append_note(notes, 0, "stapsdt", 3u, fake, sizeof(fake));

    char path[64];
    write_temp_bytes(path, notes, end);

    hex_recorder_t r = {0};
    struct attest_emitter em = {.ops = &recorder_ops, .ctx = &r};
    assert_int_equal(kernel_build_id_emit_from_path(&em, path), 0);
    assert_true(r.got_value);
    assert_int_equal(r.len, 0);

    unlink(path);
}

static void test_emit_from_path_malformed_emits_empty(void **state)
{
    (void)state;
    /* Garbage bytes that do not parse as ELF notes. The adapter should
     * recover by emitting an empty string rather than failing the whole
     * manifest emit — a corrupt /sys/kernel/notes is operationally rare
     * but should not brick attestation. */
    const uint8_t garbage[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff};
    char path[64];
    write_temp_bytes(path, garbage, sizeof(garbage));

    hex_recorder_t r = {0};
    struct attest_emitter em = {.ops = &recorder_ops, .ctx = &r};
    assert_int_equal(kernel_build_id_emit_from_path(&em, path), 0);
    assert_true(r.got_value);
    assert_int_equal(r.len, 0);

    unlink(path);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_extract_finds_gnu_build_id),
        cmocka_unit_test(test_extract_skips_non_gnu_note),
        cmocka_unit_test(test_extract_returns_minus_two_when_absent),
        cmocka_unit_test(test_extract_returns_minus_two_on_empty),
        cmocka_unit_test(test_extract_rejects_truncated_header),
        cmocka_unit_test(test_extract_rejects_truncated_note_body),
        cmocka_unit_test(test_extract_rejects_oversized_descsz),
        cmocka_unit_test(test_extract_rejects_zero_descsz),
        cmocka_unit_test(test_emit_from_path_with_real_note),
        cmocka_unit_test(test_emit_from_path_missing_file_emits_empty),
        cmocka_unit_test(test_emit_from_path_no_note_emits_empty),
        cmocka_unit_test(test_emit_from_path_malformed_emits_empty),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
