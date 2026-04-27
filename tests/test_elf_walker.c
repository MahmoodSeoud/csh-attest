/*
 * Tests for elf_walker — the userspace ELF dispatcher that locates and
 * extracts NT_GNU_BUILD_ID from on-disk ELF binaries.
 *
 * All test fixtures are constructed in-memory rather than checked in as
 * binary files. Keeps the test surface explicit (you can read what's being
 * parsed in C) and dodges the question of how to ship a stable ELF blob
 * across architectures.
 *
 * Coverage matrix (per PLAN.md test plan):
 *   - happy path: ELF64 LE with build-id in PT_NOTE
 *   - happy path: ELF32 LE with build-id
 *   - cross-endian: ELF64 BE
 *   - non-ELF input: returns NOT_ELF
 *   - ELF without PT_NOTE: returns NO_BUILDID
 *   - ELF with PT_NOTE but no GNU build-id note (stripped): NO_BUILDID
 *   - malformed: phoff past end of buffer
 *   - malformed: phnum exceeds cap
 *   - malformed: PT_NOTE filesz past end of buffer
 *   - malformed: phentsize too small for class
 *   - path mode happy path
 *   - path mode IO error
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cmocka.h>

#include "elf_walker.h"
#include "elf_note_walk.h"

/* ------------------------------------------------------------------ */
/* Fixture builders — construct minimal ELFs in a heap buffer.        */
/* ------------------------------------------------------------------ */

#define EI_CLASS  4
#define EI_DATA   5
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#define ELF32_EHDR_SIZE 52
#define ELF64_EHDR_SIZE 64
#define ELF32_PHDR_SIZE 32
#define ELF64_PHDR_SIZE 56

static void put_u16_le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put_u64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put_u16_be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void put_u64_be(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * (7 - i)));
}

/*
 * Build a single GNU build-id note: namesz=4 ("GNU\0"), descsz=20, type=3.
 * Returns total bytes written (always 32 for a 20-byte build-id: 12 header
 * + 4 padded name + 20 padded desc).
 */
static size_t put_gnu_buildid_note(uint8_t *p, const uint8_t *id, size_t id_len,
                                   int is_be)
{
    uint32_t namesz = 4, descsz = (uint32_t)id_len, type = 3;
    if (is_be) {
        put_u32_be(p + 0, namesz);
        put_u32_be(p + 4, descsz);
        put_u32_be(p + 8, type);
    } else {
        put_u32_le(p + 0, namesz);
        put_u32_le(p + 4, descsz);
        put_u32_le(p + 8, type);
    }
    memcpy(p + 12, "GNU\0", 4);
    memcpy(p + 16, id, id_len);
    /* Pad descsz up to 4-byte alignment. */
    size_t padded_desc = (id_len + 3u) & ~(size_t)3u;
    for (size_t i = id_len; i < padded_desc; i++) {
        p[16 + i] = 0;
    }
    return 16 + padded_desc;
}

/*
 * Build a complete minimal ELF64 binary in `buf` containing one PT_NOTE
 * segment with one GNU build-id note. Returns total ELF size.
 *
 * Layout:
 *   [0..63]    ELF64 header
 *   [64..119]  one Phdr64 (PT_NOTE)
 *   [120..]    notes payload
 */
static size_t build_elf64(uint8_t *buf, size_t cap,
                         const uint8_t *id, size_t id_len, int is_be)
{
    assert_true(cap >= 256);
    memset(buf, 0, cap);
    /* e_ident */
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA]  = is_be ? ELFDATA2MSB : ELFDATA2LSB;
    buf[6] = 1; /* EI_VERSION */

    void (*put16)(uint8_t *, uint16_t) = is_be ? put_u16_be : put_u16_le;
    /* (put_u32 not needed in this builder — phoff is 64-bit in ELF64) */
    void (*put64)(uint8_t *, uint64_t) = is_be ? put_u64_be : put_u64_le;

    /* e_type, e_machine, e_version (skip — zero is fine) */
    /* e_phoff = 64, e_phentsize = 56, e_phnum = 1 */
    put64(buf + 32, 64);              /* e_phoff */
    put16(buf + 54, ELF64_PHDR_SIZE); /* e_phentsize */
    put16(buf + 56, 1);               /* e_phnum */

    /* Phdr64 at offset 64 — PT_NOTE, p_offset = 120, p_filesz = note bytes. */
    uint8_t *ph = buf + 64;
    if (is_be) {
        put_u32_be(ph + 0, 4);  /* PT_NOTE */
    } else {
        put_u32_le(ph + 0, 4);
    }
    put64(ph + 8,  120);              /* p_offset */
    /* Write a placeholder filesz; updated after we know the note size. */

    size_t note_bytes = put_gnu_buildid_note(buf + 120, id, id_len, is_be);
    put64(ph + 32, note_bytes);       /* p_filesz */

    return 120 + note_bytes;
}

/*
 * Same as build_elf64 but ELF32. ELF32 header is 52 bytes, Phdr32 is 32.
 */
static size_t build_elf32(uint8_t *buf, size_t cap,
                          const uint8_t *id, size_t id_len, int is_be)
{
    assert_true(cap >= 256);
    memset(buf, 0, cap);
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS32;
    buf[EI_DATA]  = is_be ? ELFDATA2MSB : ELFDATA2LSB;
    buf[6] = 1;

    void (*put16)(uint8_t *, uint16_t) = is_be ? put_u16_be : put_u16_le;
    void (*put32)(uint8_t *, uint32_t) = is_be ? put_u32_be : put_u32_le;

    /* e_phoff = 52, e_phentsize = 32, e_phnum = 1 */
    put32(buf + 28, 52);              /* e_phoff */
    put16(buf + 42, ELF32_PHDR_SIZE); /* e_phentsize */
    put16(buf + 44, 1);               /* e_phnum */

    /* Phdr32 at offset 52 — PT_NOTE, p_offset = 84. */
    uint8_t *ph = buf + 52;
    put32(ph + 0,  4);                /* PT_NOTE */
    put32(ph + 4,  84);               /* p_offset */
    /* Skip p_vaddr, p_paddr (8 + 12 bytes) — zero. */

    size_t note_bytes = put_gnu_buildid_note(buf + 84, id, id_len, is_be);
    put32(ph + 16, (uint32_t)note_bytes);  /* p_filesz */

    return 84 + note_bytes;
}

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

static const uint8_t SAMPLE_BUILDID[20] = {
    0x5c, 0x4e, 0x1a, 0xb0, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xff, 0x00, 0x11, 0x22,
};

static void test_elf64_le_happy_path(void **state)
{
    (void)state;
    uint8_t buf[256];
    size_t n = build_elf64(buf, sizeof(buf), SAMPLE_BUILDID, 20, 0);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, n, out, &out_len);
    assert_int_equal(rc, ELF_WALKER_OK);
    assert_int_equal(out_len, 20);
    assert_memory_equal(out, SAMPLE_BUILDID, 20);
}

static void test_elf32_le_happy_path(void **state)
{
    (void)state;
    uint8_t buf[256];
    size_t n = build_elf32(buf, sizeof(buf), SAMPLE_BUILDID, 20, 0);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, n, out, &out_len);
    assert_int_equal(rc, ELF_WALKER_OK);
    assert_int_equal(out_len, 20);
    assert_memory_equal(out, SAMPLE_BUILDID, 20);
}

static void test_elf64_be_cross_endian(void **state)
{
    (void)state;
    uint8_t buf[256];
    size_t n = build_elf64(buf, sizeof(buf), SAMPLE_BUILDID, 20, 1);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, n, out, &out_len);
    assert_int_equal(rc, ELF_WALKER_OK);
    assert_int_equal(out_len, 20);
    assert_memory_equal(out, SAMPLE_BUILDID, 20);
}

static void test_elf32_be_cross_endian(void **state)
{
    (void)state;
    uint8_t buf[256];
    size_t n = build_elf32(buf, sizeof(buf), SAMPLE_BUILDID, 20, 1);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, n, out, &out_len);
    assert_int_equal(rc, ELF_WALKER_OK);
    assert_int_equal(out_len, 20);
    assert_memory_equal(out, SAMPLE_BUILDID, 20);
}

static void test_not_elf_magic(void **state)
{
    (void)state;
    uint8_t junk[64] = {0};
    /* Not the magic — bash shebang. */
    junk[0] = '#'; junk[1] = '!'; junk[2] = '/'; junk[3] = 'b';
    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(junk, sizeof(junk),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_NOT_ELF);
}

static void test_not_elf_too_short(void **state)
{
    (void)state;
    uint8_t tiny[4] = {0x7f, 'E', 'L', 'F'}; /* magic but no e_ident */
    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(tiny, sizeof(tiny),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_NOT_ELF);
}

static void test_elf_with_no_phdrs(void **state)
{
    (void)state;
    /* ELF64 LE header, e_phnum = 0. */
    uint8_t buf[ELF64_EHDR_SIZE] = {0};
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA]  = ELFDATA2LSB;
    buf[6] = 1;
    /* phnum = 0 (default zero from memset) */
    put_u16_le(buf + 54, ELF64_PHDR_SIZE);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, sizeof(buf),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_NO_BUILDID);
}

static void test_stripped_pt_note_without_gnu(void **state)
{
    (void)state;
    /* ELF64 LE with one PT_NOTE containing a non-GNU note (e.g. NT_VERSION). */
    uint8_t buf[256] = {0};
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA]  = ELFDATA2LSB;
    buf[6] = 1;
    put_u64_le(buf + 32, 64);
    put_u16_le(buf + 54, ELF64_PHDR_SIZE);
    put_u16_le(buf + 56, 1);

    /* Phdr64: PT_NOTE, p_offset=120. */
    put_u32_le(buf + 64 + 0, 4);
    put_u64_le(buf + 64 + 8, 120);

    /* Note: namesz=4, descsz=4, type=1 (NT_VERSION, NOT NT_GNU_BUILD_ID). */
    put_u32_le(buf + 120 + 0, 4);
    put_u32_le(buf + 120 + 4, 4);
    put_u32_le(buf + 120 + 8, 1);
    memcpy(buf + 120 + 12, "GNU\0", 4);
    memcpy(buf + 120 + 16, "\x01\x02\x03\x04", 4);
    put_u64_le(buf + 64 + 32, 20); /* p_filesz = 20 (12+4+4) */

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, sizeof(buf),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_NO_BUILDID);
}

static void test_malformed_phoff_past_end(void **state)
{
    (void)state;
    /* ELF64 LE header but e_phoff points past end of buffer. */
    uint8_t buf[ELF64_EHDR_SIZE] = {0};
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA]  = ELFDATA2LSB;
    buf[6] = 1;
    put_u64_le(buf + 32, 99999); /* phoff way past end */
    put_u16_le(buf + 54, ELF64_PHDR_SIZE);
    put_u16_le(buf + 56, 1);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, sizeof(buf),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_PARSE_ERROR);
}

static void test_malformed_phnum_too_large(void **state)
{
    (void)state;
    uint8_t buf[ELF64_EHDR_SIZE] = {0};
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA]  = ELFDATA2LSB;
    buf[6] = 1;
    put_u64_le(buf + 32, 64);
    put_u16_le(buf + 54, ELF64_PHDR_SIZE);
    put_u16_le(buf + 56, 9999); /* phnum well past ELF_WALKER_MAX_PHDRS */

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, sizeof(buf),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_PARSE_ERROR);
}

static void test_malformed_pt_note_filesz_overflow(void **state)
{
    (void)state;
    uint8_t buf[256] = {0};
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA]  = ELFDATA2LSB;
    buf[6] = 1;
    put_u64_le(buf + 32, 64);
    put_u16_le(buf + 54, ELF64_PHDR_SIZE);
    put_u16_le(buf + 56, 1);

    /* PT_NOTE with p_offset=120, p_filesz=99999 (past end of 256-byte buf). */
    put_u32_le(buf + 64 + 0, 4);
    put_u64_le(buf + 64 + 8, 120);
    put_u64_le(buf + 64 + 32, 99999);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, sizeof(buf),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_PARSE_ERROR);
}

static void test_malformed_phentsize_too_small(void **state)
{
    (void)state;
    uint8_t buf[ELF64_EHDR_SIZE] = {0};
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA]  = ELFDATA2LSB;
    buf[6] = 1;
    put_u64_le(buf + 32, 64);
    put_u16_le(buf + 54, 16);   /* phentsize too small for ELF64 (needs 56) */
    put_u16_le(buf + 56, 1);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_buffer(buf, sizeof(buf),
                                                    out, &out_len);
    assert_int_equal(rc, ELF_WALKER_PARSE_ERROR);
}

/* ------------------------------------------------------------------ */
/* Path-mode tests — write a temp file, walk it, clean up.            */
/* ------------------------------------------------------------------ */

static char *write_temp_elf(const uint8_t *bytes, size_t n)
{
    char *path = strdup("/tmp/test_elf_walker_XXXXXX");
    int fd = mkstemp(path);
    assert_int_not_equal(fd, -1);
    ssize_t w = write(fd, bytes, n);
    assert_int_equal((size_t)w, n);
    close(fd);
    return path;
}

static void test_path_happy_path(void **state)
{
    (void)state;
    uint8_t buf[256];
    size_t n = build_elf64(buf, sizeof(buf), SAMPLE_BUILDID, 20, 0);
    char *path = write_temp_elf(buf, n);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_path(path, out, &out_len);
    assert_int_equal(rc, ELF_WALKER_OK);
    assert_int_equal(out_len, 20);
    assert_memory_equal(out, SAMPLE_BUILDID, 20);

    unlink(path);
    free(path);
}

static void test_path_io_error(void **state)
{
    (void)state;
    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_path(
        "/tmp/this-does-not-exist-csh-attest-test", out, &out_len);
    assert_int_equal(rc, ELF_WALKER_IO_ERROR);
}

static void test_path_not_elf(void **state)
{
    (void)state;
    /* Write a non-ELF file (a shell script). */
    const char *script = "#!/bin/sh\necho hello\n";
    char *path = write_temp_elf((const uint8_t *)script, strlen(script));

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_path(path, out, &out_len);
    assert_int_equal(rc, ELF_WALKER_NOT_ELF);

    unlink(path);
    free(path);
}

static void test_path_be_cross_endian(void **state)
{
    (void)state;
    uint8_t buf[256];
    size_t n = build_elf64(buf, sizeof(buf), SAMPLE_BUILDID, 20, 1);
    char *path = write_temp_elf(buf, n);

    uint8_t out[ELF_BUILD_ID_MAX_BYTES] = {0};
    size_t out_len = 0;
    int rc = elf_walker_extract_buildid_from_path(path, out, &out_len);
    assert_int_equal(rc, ELF_WALKER_OK);
    assert_int_equal(out_len, 20);
    assert_memory_equal(out, SAMPLE_BUILDID, 20);

    unlink(path);
    free(path);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_elf64_le_happy_path),
        cmocka_unit_test(test_elf32_le_happy_path),
        cmocka_unit_test(test_elf64_be_cross_endian),
        cmocka_unit_test(test_elf32_be_cross_endian),
        cmocka_unit_test(test_not_elf_magic),
        cmocka_unit_test(test_not_elf_too_short),
        cmocka_unit_test(test_elf_with_no_phdrs),
        cmocka_unit_test(test_stripped_pt_note_without_gnu),
        cmocka_unit_test(test_malformed_phoff_past_end),
        cmocka_unit_test(test_malformed_phnum_too_large),
        cmocka_unit_test(test_malformed_pt_note_filesz_overflow),
        cmocka_unit_test(test_malformed_phentsize_too_small),
        cmocka_unit_test(test_path_happy_path),
        cmocka_unit_test(test_path_io_error),
        cmocka_unit_test(test_path_not_elf),
        cmocka_unit_test(test_path_be_cross_endian),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
