/*
 * Inner ELF note walker. Extracted from kernel_build_id.c so the userspace
 * ELF adapter (binaries.list) can reuse it on PT_NOTE segment payloads.
 *
 * ELF note layout (System V ABI; identical on Linux little- and big-endian):
 *
 *     +---------+---------+---------+---------------+---------------+
 *     | namesz  | descsz  |  type   |  name (padded)| desc (padded) |
 *     | uint32  | uint32  | uint32  |  namesz bytes |  descsz bytes |
 *     +---------+---------+---------+---------------+---------------+
 *
 * Both name and desc are padded up to 4-byte alignment. The three header
 * fields are read in the buffer's native endianness; the ELF walker is
 * responsible for byte-swapping before passing notes from a cross-endian
 * binary.
 *
 * NT_GNU_BUILD_ID = 3 (per linux/elf-em.h, glibc <elf.h>). Hard-coded
 * rather than #include <elf.h> — that header isn't portable to the macOS
 * dev compile-check target.
 */

#include "elf_note_walk.h"

#include <string.h>

#define NT_GNU_BUILD_ID_VALUE 3u

/* Round up to next multiple of 4 — ELF note name/desc padding. */
static size_t pad4(size_t n)
{
    return (n + 3u) & ~(size_t)3u;
}

int elf_note_walk_find_buildid(const uint8_t *bytes, size_t len,
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

        /* Reject overflow / truncation. Each cast catches an additive
         * overflow path; the final bound check catches a note that claims
         * to extend past the end of the buffer. */
        if (desc_off < name_off || next < desc_off || next > len) {
            return -1;
        }

        if (type == NT_GNU_BUILD_ID_VALUE && namesz == 4u &&
            memcmp(bytes + name_off, "GNU\0", 4) == 0) {
            if (descsz == 0 || descsz > ELF_BUILD_ID_MAX_BYTES) {
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
