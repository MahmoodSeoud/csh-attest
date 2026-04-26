#pragma once

/*
 * kernel.build_id adapter — captures the GNU build-id ELF note exposed by
 * the running Linux kernel at /sys/kernel/notes.
 *
 * The note's `desc` field is the cryptographic identity of the kernel
 * image — far more useful as parity evidence than `kernel.uname`, which
 * only reflects whatever release string the build system embedded.
 *
 * Linux exposes /sys/kernel/notes as a read-only file containing the
 * kernel ELF's `.notes` section verbatim. We walk it looking for a note
 * with name "GNU" (NUL-terminated, 4 bytes) and type NT_GNU_BUILD_ID (3);
 * the desc bytes are the build-id (typically 20 bytes / SHA-1).
 *
 * Non-Linux dev path (macOS et al.) → empty string placeholder.
 * /sys/kernel/notes missing or no GNU note on Linux → also empty string.
 * Deterministic in every case so the canonical hash stays stable across
 * runs on the same host.
 *
 * Per design doc 1F: kernel.build_id has a 64-byte size budget. A typical
 * build-id is 20 bytes ⇒ 40 hex chars + 2 quotes = 42 bytes; well under.
 *
 * The path-taking helper exists so unit tests can craft a temp file with
 * known note content. The production adapter wraps it with the canonical
 * Linux path (/sys/kernel/notes).
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Largest build-id we'll accept from the notes blob. SHA-1 is 20 bytes;
 * SHA-256 (which some recent toolchains emit) is 32. We refuse anything
 * larger — would imply a malformed note or an unfamiliar hash algorithm
 * we should not silently truncate.
 */
#define KERNEL_BUILD_ID_MAX_BYTES 32u

/*
 * Walk an in-memory ELF .notes payload; if a GNU build-id note is found,
 * write its desc bytes into `out` (caller provides at least
 * KERNEL_BUILD_ID_MAX_BYTES of storage) and set `*out_len`.
 *
 * Returns:
 *    0 — found and written
 *   -1 — payload is truncated, malformed, or carries a build-id larger
 *        than KERNEL_BUILD_ID_MAX_BYTES
 *   -2 — payload is well-formed but contains no GNU build-id note
 */
int kernel_build_id_extract(const uint8_t *bytes, size_t len,
                            uint8_t *out, size_t *out_len);

/*
 * Read the supplied file (e.g. "/sys/kernel/notes") and emit the build-id
 * via the canonical emitter as a lowercase hex string. File missing or
 * note absent → empty string emitted (deterministic placeholder).
 *
 * Returns the emitter's last return code (or 0 on the empty-string path).
 */
struct attest_emitter;
int kernel_build_id_emit_from_path(struct attest_emitter *em,
                                   const char *path);

#ifdef __cplusplus
}
#endif
