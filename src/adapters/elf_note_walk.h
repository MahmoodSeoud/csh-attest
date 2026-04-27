#pragma once

/*
 * ELF .notes section walker. Pure parser — given a buffer of ELF note
 * records, extract a GNU build-id (NT_GNU_BUILD_ID, name "GNU") if present.
 *
 * The kernel adapter feeds /sys/kernel/notes content directly; the
 * userspace ELF adapter (binaries.list) feeds the bytes pointed to by a
 * PT_NOTE program-header entry. Layout is identical in both cases — see
 * the System V ABI ELF spec / linux/elf-em.h.
 *
 * The walker is endian-agnostic at the FILE level (each note record's
 * namesz/descsz/type are read in whatever endianness the buffer is in,
 * which is the host endianness for /sys/kernel/notes and for any ELF
 * built for the running architecture). For cross-compiled userspace ELFs
 * the higher-level ELF walker handles the byte-swap before calling here.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Largest build-id we'll accept. SHA-1 is 20 bytes; SHA-256 (some recent
 * toolchains) is 32. Anything larger is malformed or an unfamiliar hash
 * algorithm we should not silently truncate.
 */
#define ELF_BUILD_ID_MAX_BYTES 32u

/*
 * Walk an in-memory ELF .notes payload; on the first NT_GNU_BUILD_ID note
 * with name "GNU\0" found, copy its desc bytes into `out` (caller provides
 * at least ELF_BUILD_ID_MAX_BYTES of storage) and write the length to
 * `*out_len`.
 *
 * Returns:
 *    0 — found and written
 *   -1 — payload is truncated, malformed, or carries a build-id larger
 *        than ELF_BUILD_ID_MAX_BYTES
 *   -2 — payload is well-formed but contains no GNU build-id note
 */
int elf_note_walk_find_buildid(const uint8_t *bytes, size_t len,
                               uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif
