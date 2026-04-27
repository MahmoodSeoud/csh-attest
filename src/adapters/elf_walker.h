#pragma once

/*
 * Userspace ELF walker — locates the GNU build-id in an on-disk ELF file
 * by parsing the ELF header, walking program headers to find PT_NOTE
 * segments, and delegating note extraction to elf_note_walk.
 *
 * This is the new code the v0.5.0 plan said it would be (NOT a "lift" of
 * kernel_build_id_extract — that walker only handles already-extracted
 * notes-section bytes, which is what /sys/kernel/notes exposes; userspace
 * binaries are full ELF files and require ELF-header dispatch first).
 *
 * Supports both ELF32 and ELF64, both endiannesses (a cross-compiled
 * armv7-BE bird-side ELF on an x86_64-LE host parses correctly).
 *
 * Per the v0.5.0 plan determinism contract:
 *   - Not an ELF (magic mismatch) → return ELF_WALKER_NOT_ELF; caller
 *     decides whether to fall back to content-hash or treat as error.
 *   - ELF without NT_GNU_BUILD_ID note → return ELF_WALKER_NO_BUILDID;
 *     stripped binaries land here, caller MUST fall back to content-hash
 *     so the manifest entry is non-empty (the silent-empty failure mode
 *     the plan exists to prevent).
 *   - ELF with build-id → ELF_WALKER_OK; build_id + len written.
 *
 * Bounded reads only — does not slurp whole binaries. Largest fixed read
 * is e_phnum * e_phentsize bytes (the program-header table); per-note
 * read is the PT_NOTE segment's p_filesz, capped at ELF_WALKER_MAX_NOTES_BYTES.
 */

#include <stddef.h>
#include <stdint.h>

/*
 * Caller's `out` buffer must hold at least ELF_BUILD_ID_MAX_BYTES (32),
 * defined by elf_note_walk.h.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for elf_walker_extract_buildid_*. */
#define ELF_WALKER_OK           0   /* build-id found and written       */
#define ELF_WALKER_NOT_ELF     -1   /* ELF magic missing                */
#define ELF_WALKER_PARSE_ERROR -2   /* malformed header / overflow      */
#define ELF_WALKER_NO_BUILDID  -3   /* well-formed ELF, no build-id note*/
#define ELF_WALKER_IO_ERROR    -4   /* fopen/fread failure              */

/*
 * Cap on PT_NOTE segment size. Real userspace ELFs ship < 4 KB of notes
 * total; cap at 64 KB to bound a single read while leaving headroom for
 * pathological-but-legitimate build artifacts.
 */
#define ELF_WALKER_MAX_NOTES_BYTES 65536u

/*
 * Cap on total program-header table size (e_phnum * e_phentsize). A
 * userspace ELF with > 1024 program headers is malformed in practice.
 * Bounds the heap allocation in the path variant.
 */
#define ELF_WALKER_MAX_PHDRS 1024u

/*
 * Pure parser — operates on an in-memory ELF buffer. Tests construct
 * minimal ELFs in-process and exercise this directly without filesystem
 * dependence. Production code uses elf_walker_extract_buildid_from_path.
 *
 * `bytes` / `len` describe the entire ELF file (header + phdrs + notes).
 * `out` must hold at least ELF_BUILD_ID_MAX_BYTES.
 *
 * Returns one of the ELF_WALKER_* codes above.
 */
int elf_walker_extract_buildid_from_buffer(const uint8_t *bytes, size_t len,
                                           uint8_t *out, size_t *out_len);

/*
 * Production entry point. Opens `path`, reads only the bytes the parser
 * needs (ELF header → program headers → each PT_NOTE segment), and writes
 * the build-id on success.
 *
 * Returns one of the ELF_WALKER_* codes. ELF_WALKER_IO_ERROR distinguishes
 * "couldn't even open the file" from "file isn't an ELF" — important for
 * the binaries.list adapter's error reporting.
 */
int elf_walker_extract_buildid_from_path(const char *path,
                                         uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif
