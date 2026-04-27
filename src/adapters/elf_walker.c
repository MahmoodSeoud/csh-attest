/*
 * Userspace ELF walker — see elf_walker.h.
 *
 * ELF spec excerpts (System V ABI gen-4 / linux/elf.h):
 *
 *   e_ident[16]:
 *     [0..3] = magic = "\x7fELF"
 *     [4]    = EI_CLASS:  1 = ELFCLASS32, 2 = ELFCLASS64
 *     [5]    = EI_DATA:   1 = ELFDATA2LSB (LE), 2 = ELFDATA2MSB (BE)
 *
 *   ELF32 header (52 B):
 *     e_phoff  @28 (4 B), e_phentsize @42 (2 B), e_phnum @44 (2 B)
 *
 *   ELF64 header (64 B):
 *     e_phoff  @32 (8 B), e_phentsize @54 (2 B), e_phnum @56 (2 B)
 *
 *   Phdr32 (32 B): type(4) offset(4) vaddr(4) paddr(4) filesz(4) ...
 *   Phdr64 (56 B): type(4) flags(4) offset(8) vaddr(8) paddr(8) filesz(8) ...
 *     ^^ note: ELF64 swaps `flags` ahead of `offset` vs ELF32. Field
 *        offsets are NOT a simple "shift to 64-bit" of ELF32.
 *
 *   PT_NOTE = 4
 */

#include "elf_walker.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_note_walk.h"

#define EI_NIDENT     16
#define EI_CLASS       4
#define EI_DATA        5
#define ELFCLASS32     1
#define ELFCLASS64     2
#define ELFDATA2LSB    1
#define ELFDATA2MSB    2
#define PT_NOTE        4u

#define ELF32_EHDR_SIZE 52u
#define ELF64_EHDR_SIZE 64u
#define ELF32_PHDR_SIZE 32u
#define ELF64_PHDR_SIZE 56u

/* Field offsets within the ELF header, post-e_ident. */
#define ELF32_EHDR_PHOFF      28u
#define ELF32_EHDR_PHENTSIZE  42u
#define ELF32_EHDR_PHNUM      44u
#define ELF64_EHDR_PHOFF      32u
#define ELF64_EHDR_PHENTSIZE  54u
#define ELF64_EHDR_PHNUM      56u

/* Field offsets within Phdr32 / Phdr64 — note ELF64 reordering. */
#define PHDR32_TYPE      0u
#define PHDR32_OFFSET    4u
#define PHDR32_FILESZ   16u

#define PHDR64_TYPE      0u
#define PHDR64_OFFSET    8u
#define PHDR64_FILESZ   32u

/* ------------------------------------------------------------------ */
/* Endian-aware integer reads.                                         */
/* All ELF integer fields are unsigned and read in the file's native   */
/* endianness (per EI_DATA). Use memcpy for unaligned access.          */
/* ------------------------------------------------------------------ */

static uint16_t read_u16(const uint8_t *p, int is_be)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    if (is_be) {
        v = (uint16_t)(((v & 0xFFu) << 8) | ((v >> 8) & 0xFFu));
    }
    return v;
}

static uint32_t read_u32(const uint8_t *p, int is_be)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    if (is_be) {
        v = ((v & 0xFFu) << 24) |
            (((v >> 8) & 0xFFu) << 16) |
            (((v >> 16) & 0xFFu) << 8) |
            ((v >> 24) & 0xFFu);
    }
    return v;
}

static uint64_t read_u64(const uint8_t *p, int is_be)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    if (is_be) {
        uint64_t r = 0;
        for (int i = 0; i < 8; i++) {
            r = (r << 8) | (v & 0xFFu);
            v >>= 8;
        }
        v = r;
    }
    return v;
}

/* ------------------------------------------------------------------ */
/* Byte-swap a notes payload in place if the ELF is cross-endian.     */
/* elf_note_walk_find_buildid reads namesz/descsz/type via host-order */
/* memcpy, so cross-endian notes need swapping before the call. The   */
/* note name + desc are byte-strings (not multibyte ints) so they     */
/* don't get swapped — only the three header fields per record do.    */
/* ------------------------------------------------------------------ */

static int swap_notes_inplace(uint8_t *bytes, size_t len)
{
    size_t pos = 0;
    while (pos + 12u <= len) {
        for (int field = 0; field < 3; field++) {
            uint8_t *p = bytes + pos + (size_t)field * 4u;
            uint8_t t;
            t = p[0]; p[0] = p[3]; p[3] = t;
            t = p[1]; p[1] = p[2]; p[2] = t;
        }
        uint32_t namesz, descsz;
        memcpy(&namesz, bytes + pos + 0, sizeof(namesz));
        memcpy(&descsz, bytes + pos + 4, sizeof(descsz));

        size_t pad4_namesz = (namesz + 3u) & ~(size_t)3u;
        size_t pad4_descsz = (descsz + 3u) & ~(size_t)3u;
        size_t name_off = pos + 12u;
        size_t desc_off = name_off + pad4_namesz;
        size_t next     = desc_off + pad4_descsz;

        if (desc_off < name_off || next < desc_off || next > len) {
            return -1;
        }
        pos = next;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Buffer-mode parser.                                                 */
/* ------------------------------------------------------------------ */

int elf_walker_extract_buildid_from_buffer(const uint8_t *bytes, size_t len,
                                           uint8_t *out, size_t *out_len)
{
    if (bytes == NULL || out == NULL || out_len == NULL) {
        return ELF_WALKER_PARSE_ERROR;
    }
    if (len < EI_NIDENT) {
        return ELF_WALKER_NOT_ELF;
    }
    /* Magic. */
    if (!(bytes[0] == 0x7f && bytes[1] == 'E' &&
          bytes[2] == 'L'  && bytes[3] == 'F')) {
        return ELF_WALKER_NOT_ELF;
    }

    int is_64;
    if (bytes[EI_CLASS] == ELFCLASS64) {
        is_64 = 1;
    } else if (bytes[EI_CLASS] == ELFCLASS32) {
        is_64 = 0;
    } else {
        return ELF_WALKER_PARSE_ERROR;
    }

    int is_be;
    if (bytes[EI_DATA] == ELFDATA2MSB) {
        is_be = 1;
    } else if (bytes[EI_DATA] == ELFDATA2LSB) {
        is_be = 0;
    } else {
        return ELF_WALKER_PARSE_ERROR;
    }

    size_t ehdr_size = is_64 ? ELF64_EHDR_SIZE : ELF32_EHDR_SIZE;
    if (len < ehdr_size) {
        return ELF_WALKER_PARSE_ERROR;
    }

    uint64_t phoff;
    uint16_t phentsize, phnum;
    if (is_64) {
        phoff     = read_u64(bytes + ELF64_EHDR_PHOFF,     is_be);
        phentsize = read_u16(bytes + ELF64_EHDR_PHENTSIZE, is_be);
        phnum     = read_u16(bytes + ELF64_EHDR_PHNUM,     is_be);
    } else {
        phoff     = (uint64_t)read_u32(bytes + ELF32_EHDR_PHOFF, is_be);
        phentsize = read_u16(bytes + ELF32_EHDR_PHENTSIZE,        is_be);
        phnum     = read_u16(bytes + ELF32_EHDR_PHNUM,            is_be);
    }

    /* No program headers → no PT_NOTE → no build-id (but a valid ELF). */
    if (phnum == 0) {
        return ELF_WALKER_NO_BUILDID;
    }
    if (phnum > ELF_WALKER_MAX_PHDRS) {
        return ELF_WALKER_PARSE_ERROR;
    }
    /* Sanity: phentsize matches the spec for the class. Linkers in the
     * wild MAY emit larger phentsize for forward-compat, but the fields
     * we read are at fixed offsets within the first 56 bytes for ELF64
     * and 32 bytes for ELF32, so as long as phentsize >= those minimums
     * we can still walk. Clamp the upper end for sanity. */
    size_t min_phentsize = is_64 ? ELF64_PHDR_SIZE : ELF32_PHDR_SIZE;
    if (phentsize < min_phentsize || phentsize > 256u) {
        return ELF_WALKER_PARSE_ERROR;
    }

    /* Bounds-check the program-header table. */
    if (phoff > len) {
        return ELF_WALKER_PARSE_ERROR;
    }
    uint64_t phtab_size = (uint64_t)phentsize * (uint64_t)phnum;
    if (phtab_size > len - phoff) {
        return ELF_WALKER_PARSE_ERROR;
    }

    /* Walk program headers, find each PT_NOTE, dispatch to note walker. */
    int saw_pt_note = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = bytes + phoff + (uint64_t)i * phentsize;
        uint32_t p_type = read_u32(ph + (is_64 ? PHDR64_TYPE : PHDR32_TYPE),
                                   is_be);
        if (p_type != PT_NOTE) {
            continue;
        }
        saw_pt_note = 1;

        uint64_t p_offset, p_filesz;
        if (is_64) {
            p_offset = read_u64(ph + PHDR64_OFFSET, is_be);
            p_filesz = read_u64(ph + PHDR64_FILESZ, is_be);
        } else {
            p_offset = (uint64_t)read_u32(ph + PHDR32_OFFSET, is_be);
            p_filesz = (uint64_t)read_u32(ph + PHDR32_FILESZ, is_be);
        }

        /* Bounds-check the segment. */
        if (p_offset > len || p_filesz > len - p_offset) {
            return ELF_WALKER_PARSE_ERROR;
        }
        if (p_filesz == 0 || p_filesz > ELF_WALKER_MAX_NOTES_BYTES) {
            /* Empty segment or pathological — skip (or reject as malformed
             * if we cared more). Caller would still rather see "no build-id"
             * than "parse error" if some other PT_NOTE has the build-id. */
            continue;
        }

        /* Cross-endian: copy to a scratch buffer and byte-swap header
         * fields per record before calling the (host-order) note walker. */
        if (is_be) {
            uint8_t *scratch = malloc((size_t)p_filesz);
            if (scratch == NULL) {
                return ELF_WALKER_PARSE_ERROR;
            }
            memcpy(scratch, bytes + p_offset, (size_t)p_filesz);
            int sw = swap_notes_inplace(scratch, (size_t)p_filesz);
            int rc;
            if (sw < 0) {
                rc = ELF_WALKER_PARSE_ERROR;
            } else {
                int found = elf_note_walk_find_buildid(
                    scratch, (size_t)p_filesz, out, out_len);
                if (found == 0) {
                    rc = ELF_WALKER_OK;
                } else if (found == -1) {
                    rc = ELF_WALKER_PARSE_ERROR;
                } else {
                    rc = -100; /* sentinel: try next PT_NOTE */
                }
            }
            free(scratch);
            if (rc == ELF_WALKER_OK || rc == ELF_WALKER_PARSE_ERROR) {
                return rc;
            }
            /* else: try next PT_NOTE */
        } else {
            int found = elf_note_walk_find_buildid(
                bytes + p_offset, (size_t)p_filesz, out, out_len);
            if (found == 0) {
                return ELF_WALKER_OK;
            }
            if (found == -1) {
                return ELF_WALKER_PARSE_ERROR;
            }
            /* found == -2: no build-id in THIS segment, try next. */
        }
    }

    return saw_pt_note ? ELF_WALKER_NO_BUILDID : ELF_WALKER_NO_BUILDID;
}

/* ------------------------------------------------------------------ */
/* Path-mode parser. Bounded reads only — never slurps the whole file.*/
/* ------------------------------------------------------------------ */

int elf_walker_extract_buildid_from_path(const char *path,
                                         uint8_t *out, size_t *out_len)
{
    if (path == NULL || out == NULL || out_len == NULL) {
        return ELF_WALKER_PARSE_ERROR;
    }
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return ELF_WALKER_IO_ERROR;
    }

    /* Step 1: read e_ident + enough of the header to know the class. */
    uint8_t ident[EI_NIDENT];
    if (fread(ident, 1, EI_NIDENT, f) != EI_NIDENT) {
        fclose(f);
        return ELF_WALKER_NOT_ELF;
    }
    if (!(ident[0] == 0x7f && ident[1] == 'E' &&
          ident[2] == 'L'  && ident[3] == 'F')) {
        fclose(f);
        return ELF_WALKER_NOT_ELF;
    }

    int is_64;
    if (ident[EI_CLASS] == ELFCLASS64) {
        is_64 = 1;
    } else if (ident[EI_CLASS] == ELFCLASS32) {
        is_64 = 0;
    } else {
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }
    int is_be;
    if (ident[EI_DATA] == ELFDATA2MSB) {
        is_be = 1;
    } else if (ident[EI_DATA] == ELFDATA2LSB) {
        is_be = 0;
    } else {
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }

    /* Step 2: read the rest of the ELF header. */
    size_t ehdr_size = is_64 ? ELF64_EHDR_SIZE : ELF32_EHDR_SIZE;
    uint8_t ehdr[ELF64_EHDR_SIZE];
    memcpy(ehdr, ident, EI_NIDENT);
    size_t rest = ehdr_size - EI_NIDENT;
    if (fread(ehdr + EI_NIDENT, 1, rest, f) != rest) {
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }

    uint64_t phoff;
    uint16_t phentsize, phnum;
    if (is_64) {
        phoff     = read_u64(ehdr + ELF64_EHDR_PHOFF,     is_be);
        phentsize = read_u16(ehdr + ELF64_EHDR_PHENTSIZE, is_be);
        phnum     = read_u16(ehdr + ELF64_EHDR_PHNUM,     is_be);
    } else {
        phoff     = (uint64_t)read_u32(ehdr + ELF32_EHDR_PHOFF, is_be);
        phentsize = read_u16(ehdr + ELF32_EHDR_PHENTSIZE,        is_be);
        phnum     = read_u16(ehdr + ELF32_EHDR_PHNUM,            is_be);
    }

    if (phnum == 0) {
        fclose(f);
        return ELF_WALKER_NO_BUILDID;
    }
    if (phnum > ELF_WALKER_MAX_PHDRS) {
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }
    size_t min_phentsize = is_64 ? ELF64_PHDR_SIZE : ELF32_PHDR_SIZE;
    if (phentsize < min_phentsize || phentsize > 256u) {
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }

    /* Step 3: read the program-header table. */
    if (fseek(f, (long)phoff, SEEK_SET) != 0) {
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }
    size_t phtab_size = (size_t)phentsize * (size_t)phnum;
    uint8_t *phtab = malloc(phtab_size);
    if (phtab == NULL) {
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }
    if (fread(phtab, 1, phtab_size, f) != phtab_size) {
        free(phtab);
        fclose(f);
        return ELF_WALKER_PARSE_ERROR;
    }

    /* Step 4: for each PT_NOTE, seek + read + walk. */
    int rc = ELF_WALKER_NO_BUILDID;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = phtab + (size_t)i * phentsize;
        uint32_t p_type = read_u32(ph + (is_64 ? PHDR64_TYPE : PHDR32_TYPE),
                                   is_be);
        if (p_type != PT_NOTE) {
            continue;
        }
        uint64_t p_offset, p_filesz;
        if (is_64) {
            p_offset = read_u64(ph + PHDR64_OFFSET, is_be);
            p_filesz = read_u64(ph + PHDR64_FILESZ, is_be);
        } else {
            p_offset = (uint64_t)read_u32(ph + PHDR32_OFFSET, is_be);
            p_filesz = (uint64_t)read_u32(ph + PHDR32_FILESZ, is_be);
        }
        if (p_filesz == 0 || p_filesz > ELF_WALKER_MAX_NOTES_BYTES) {
            continue;
        }

        if (fseek(f, (long)p_offset, SEEK_SET) != 0) {
            rc = ELF_WALKER_PARSE_ERROR;
            break;
        }
        uint8_t *notes = malloc((size_t)p_filesz);
        if (notes == NULL) {
            rc = ELF_WALKER_PARSE_ERROR;
            break;
        }
        if (fread(notes, 1, (size_t)p_filesz, f) != p_filesz) {
            free(notes);
            rc = ELF_WALKER_PARSE_ERROR;
            break;
        }

        if (is_be) {
            if (swap_notes_inplace(notes, (size_t)p_filesz) < 0) {
                free(notes);
                rc = ELF_WALKER_PARSE_ERROR;
                break;
            }
        }

        int found = elf_note_walk_find_buildid(notes, (size_t)p_filesz,
                                               out, out_len);
        free(notes);

        if (found == 0) {
            rc = ELF_WALKER_OK;
            break;
        }
        if (found == -1) {
            rc = ELF_WALKER_PARSE_ERROR;
            break;
        }
        /* found == -2: try next PT_NOTE */
    }

    free(phtab);
    fclose(f);
    return rc;
}
