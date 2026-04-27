#pragma once

/*
 * Mission allowlist loader. Two layers:
 *
 *   Tier 1 — compile-time defaults baked in via meson options
 *            (binaries_paths, files_paths). See meson_options.txt.
 *            Generated header at build/config_defaults.h.
 *
 *   Tier 2 — runtime override at /etc/csh-attest/paths.allow.
 *            Replaces Tier 1 entirely when present (no merging).
 *            Self-attested: when loaded, its SHA-256 lands in
 *            files.merkle as a fixed slot.
 *            (Tier 2 ships in piece 6; this header reserves the API.)
 *
 * Loaded paths are sorted (byte order) and deduplicated, satisfying the
 * SCHEMA.md determinism contract: same paths in different config-file
 * order produce identical manifests.
 *
 * Per-kind hard cap: 512 entries. Overflow → ATTEST_CONFIG_E106. Lower
 * than the SCHEMA.md 200 KB envelope cap with margin for existing fields
 * + dual-hash overhead. Refusal-to-emit, not silent truncation.
 *
 * Path validation (Tier 2 only — Tier 1 is build-time-trusted):
 *   - Path must start with '/' (absolute).
 *   - Path must not contain ".." segment.
 *   - Path must not begin with /proc/, /sys/, /dev/.
 *
 * Tier 1 paths are NOT validated at load time — the assumption is that
 * mission engineers building the .so know what they're putting in. They
 * fail loudly at emit time (E301: configured path resolved to nothing)
 * if the bird's rootfs doesn't have what the .so expected.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Per-kind cap. 512 binaries × ~80 B + 512 files × ~120 B = ~100 KB,
 * leaves the SCHEMA.md 200 KB envelope cap with comfortable margin
 * (existing fields + sign envelope + dual-hash overhead).
 */
#define ATTEST_CONFIG_MAX_PATHS_PER_KIND 512u

/* Error codes (mirror SCHEMA.md / README "Error codes" table). */
#define ATTEST_CONFIG_OK         0
#define ATTEST_CONFIG_E106      -106  /* allowlist size cap breached  */
#define ATTEST_CONFIG_E_PATH    -200  /* invalid path (Tier 2)        */
#define ATTEST_CONFIG_E_OOM     -201  /* allocation failure           */
#define ATTEST_CONFIG_E_IO      -202  /* paths.allow IO failure       */
#define ATTEST_CONFIG_E_PARSE   -203  /* paths.allow parse failure    */

typedef struct {
    char **paths;     /* owned, sorted byte-wise, deduplicated */
    size_t n;
} attest_path_list_t;

typedef struct {
    attest_path_list_t binaries;
    attest_path_list_t files;
    /*
     * If Tier 2 paths.allow was loaded, holds its absolute path so the
     * binaries.list / files.merkle adapters can self-attest the config
     * file's content. NULL if Tier 1 only. (Reserved for piece 6.)
     */
    char *paths_allow_path;
} attest_config_t;

/*
 * Load mission allowlist into *out.
 *
 * Reads /etc/csh-attest/paths.allow if present (Tier 2 — piece 6),
 * otherwise falls back to compile-time defaults (Tier 1). Sorts +
 * dedups + caps. Caller owns the returned struct and must call
 * attest_config_free.
 *
 * Returns ATTEST_CONFIG_OK on success or one of the error codes above.
 */
int attest_config_load(attest_config_t *out);

/*
 * Free all storage owned by `cfg`. Safe to call on a zero-initialized
 * struct.
 */
void attest_config_free(attest_config_t *cfg);

/*
 * Lower-level loader: build a path list from an explicit array of paths
 * (NULL-terminated). Sorts, dedups, validates if `validate` is non-zero.
 * Used by both Tier 1 (validate=0) and Tier 2 (validate=1) paths.
 *
 * Exposed for tests; production code uses attest_config_load.
 */
int attest_config_path_list_from_array(attest_path_list_t *out,
                                       const char *const *paths,
                                       int validate);

/*
 * Validate a single path per Tier 2 rules. Returns ATTEST_CONFIG_OK or
 * ATTEST_CONFIG_E_PATH. Exposed for tests; production code goes through
 * attest_config_path_list_from_array.
 */
int attest_config_validate_path(const char *path);

/*
 * Process-wide cached config accessor. First call lazily invokes
 * attest_config_load() into a static struct; subsequent calls return
 * the same pointer. Returns NULL if the load failed (caller treats as
 * "no allowlist" — empty manifest fields, deterministic placeholder).
 *
 * The cache lives for the APM's lifetime. Mid-run paths.allow edits
 * require an APM reload. Documented in README + CHANGELOG.
 *
 * Not thread-safe. The csh APM is single-threaded; the bird-side CSP
 * server thread doesn't enter the attest pipeline.
 *
 * Tests can reset the cache via attest_config_reset_cache_for_testing.
 */
const attest_config_t *attest_config_get(void);

/*
 * Test-only: drop the cached config so the next attest_config_get()
 * triggers a fresh load. Production code should never call this.
 */
void attest_config_reset_cache_for_testing(void);

#ifdef __cplusplus
}
#endif
