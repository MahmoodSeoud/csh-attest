#pragma once

/*
 * binaries.list adapter — emits an array of {path, build_id, sha256}
 * entries for every ELF in the configured allowlist.
 *
 * Per v0.5.0 plan (gate-approved decisions 5, 6):
 *   - Walks attest_config_get()->binaries (Tier 1 + Tier 2 merged).
 *   - For directory entries: scandir + lexical sort, non-recursive.
 *   - For each file: dual-hash. build_id from elf_walker (empty for
 *     non-ELF or stripped ELF), sha256 over content (always).
 *   - Per-file 64 MB content cap (E107). Files larger emit empty hashes
 *     plus a verbose-mode warning (skipped silently from directories).
 *   - Symlinks skipped in v0.5.0; v0.5.1 adds lstat-tagged emission.
 *     This keeps determinism honest until the symlink semantics ship
 *     in SCHEMA.md.
 *   - Missing path (configured but absent on rootfs) → emit one entry
 *     with empty hashes + E301 stderr line ("configured path not
 *     present on this rootfs"). Manifest stays deterministic.
 *
 * Output JSON shape (one object per entry, alphabetical keys):
 *   [
 *     {"build_id":"a3f2…","path":"/usr/bin/payload","sha256":"7c4e…"},
 *     {"build_id":"","path":"/usr/bin/script.sh","sha256":""},
 *     ...
 *   ]
 *
 * Empty array if config is empty or NULL — matches v0.4.x byte semantics
 * for the rest of the manifest, just adds an empty `binaries.list` field.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Per-file content size cap. Files larger emit empty sha256 with a
 * verbose-mode warning. Bounds memory + I/O on accidental config
 * mistakes (e.g. an unbounded /var/log path in the allowlist). */
#define BINARIES_LIST_MAX_FILE_BYTES (64u * 1024u * 1024u)

struct attest_emitter;

/*
 * Walker entry point — registered in attest_fields[] in attest.c.
 * Reads the cached config via attest_config_get() and emits the
 * canonical JSON array.
 */
int attest_adapter_binaries_list(struct attest_emitter *em);

#ifdef __cplusplus
}
#endif
