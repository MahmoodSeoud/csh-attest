/*
 * kernel.build_id adapter implementation. See kernel_build_id.h for the
 * algorithm + cross-platform contract.
 *
 * ELF note layout (per System V ABI; same on Linux little- and big-endian):
 *
 *     +---------+---------+---------+---------------+---------------+
 *     | namesz  | descsz  |  type   |  name (padded)| desc (padded) |
 *     | uint32  | uint32  | uint32  |  namesz bytes |  descsz bytes |
 *     +---------+---------+---------+---------------+---------------+
 *
 * Both `name` and `desc` are padded up to 4-byte alignment. Endianness is
 * the host's — the kernel exposes its own image's notes verbatim, and the
 * userspace tool reading /sys/kernel/notes is by definition the same
 * endianness as the kernel.
 *
 * NT_GNU_BUILD_ID = 3 (per linux/elf-em.h, glibc <elf.h>). We hard-code
 * the value rather than #include <elf.h> — that header isn't portable to
 * the macOS dev compile-check target.
 */

#include "kernel_build_id.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attest.h"

#define NT_GNU_BUILD_ID_VALUE 3u

/* Round up to next multiple of 4 — ELF note name/desc padding. */
static size_t pad4(size_t n)
{
    return (n + 3u) & ~(size_t)3u;
}

int kernel_build_id_extract(const uint8_t *bytes, size_t len,
                            uint8_t *out, size_t *out_len)
{
    size_t pos = 0;
    while (pos + 12u <= len) {
        uint32_t namesz, descsz, type;
        memcpy(&namesz, bytes + pos + 0, sizeof(namesz));
        memcpy(&descsz, bytes + pos + 4, sizeof(descsz));
        memcpy(&type,   bytes + pos + 8, sizeof(type));

        size_t name_off = pos + 12u;
        size_t desc_off = name_off + pad4(namesz);
        size_t next     = desc_off + pad4(descsz);

        /* Reject overflow / truncation. Each cast catches the additive
         * overflow path; the final bound check catches a note that claims
         * to extend past the end of the buffer. */
        if (desc_off < name_off || next < desc_off || next > len) {
            return -1;
        }

        if (type == NT_GNU_BUILD_ID_VALUE && namesz == 4u &&
            memcmp(bytes + name_off, "GNU\0", 4) == 0) {
            if (descsz == 0 || descsz > KERNEL_BUILD_ID_MAX_BYTES) {
                return -1;
            }
            memcpy(out, bytes + desc_off, descsz);
            *out_len = descsz;
            return 0;
        }
        pos = next;
    }
    return -2;
}

/*
 * Slurp `path` into a heap buffer. /sys/kernel/notes is small (typically
 * <1 KB on a modern kernel); 64 KB caps memory in case of a synthetic
 * giant file and is well above any realistic .notes section size.
 */
static int slurp(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    enum { CAP = 64u * 1024u };
    uint8_t *buf = malloc(CAP);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    size_t total = 0;
    while (total < CAP) {
        size_t r = fread(buf + total, 1, CAP - total, f);
        if (r == 0) {
            break;
        }
        total += r;
    }
    int err = ferror(f);
    fclose(f);
    if (err) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = total;
    return 0;
}

int kernel_build_id_emit_from_path(struct attest_emitter *em, const char *path)
{
    uint8_t build_id[KERNEL_BUILD_ID_MAX_BYTES];
    size_t build_id_len = 0;

    uint8_t *bytes = NULL;
    size_t len = 0;
    if (slurp(path, &bytes, &len) == 0) {
        if (kernel_build_id_extract(bytes, len, build_id, &build_id_len) != 0) {
            build_id_len = 0;
        }
        free(bytes);
    }
    /* On Linux without /sys/kernel/notes, or on non-Linux dev, build_id_len
     * stays 0 and the emitter writes "" — deterministic placeholder. */
    return em->ops->value_bytes_hex(em->ctx, build_id, build_id_len);
}

int attest_adapter_kernel_build_id(struct attest_emitter *em)
{
    return kernel_build_id_emit_from_path(em, "/sys/kernel/notes");
}
