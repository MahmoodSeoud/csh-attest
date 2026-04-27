/*
 * binaries.list adapter implementation. See binaries_list.h.
 *
 * Two layers in this file:
 *   1. emit_one_file: hash one path, emit one {path,build_id,sha256}
 *      object. Pure with respect to the filesystem (just reads, no state).
 *   2. attest_adapter_binaries_list: top-level walker. Reads config,
 *      decides directory-vs-file per entry, calls emit_one_file.
 *
 * The directory walk uses scandir+alphasort for deterministic order
 * (matches modules_list.c's pattern). Symlinks (S_ISLNK) are skipped in
 * v0.5.0 — see binaries_list.h for the v0.5.1 follow-up.
 *
 * Verbose warnings (ATTEST_VERBOSE=1) go to stderr, gated to one line
 * per surprise so syslog doesn't drown.
 */

#include "binaries_list.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <sodium.h>

#include "attest.h"
#include "config.h"
#include "elf_walker.h"
#include "elf_note_walk.h"

/* ------------------------------------------------------------------ */
/* Verbose helper                                                      */
/* ------------------------------------------------------------------ */

static int verbose_enabled(void)
{
    const char *v = getenv("ATTEST_VERBOSE");
    return v != NULL && v[0] == '1' && v[1] == '\0';
}

/* ------------------------------------------------------------------ */
/* Emit a single {path, build_id, sha256} object.                      */
/* ------------------------------------------------------------------ */

static int hash_file_content(const char *path, uint8_t out[32], int *too_large)
{
    *too_large = 0;
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);

    uint8_t buf[8192];
    size_t total = 0;
    for (;;) {
        size_t r = fread(buf, 1, sizeof(buf), f);
        if (r == 0) {
            break;
        }
        total += r;
        if (total > BINARIES_LIST_MAX_FILE_BYTES) {
            *too_large = 1;
            fclose(f);
            return -1;
        }
        crypto_hash_sha256_update(&st, buf, r);
    }
    int err = ferror(f);
    fclose(f);
    if (err) {
        return -1;
    }
    crypto_hash_sha256_final(&st, out);
    return 0;
}

/*
 * Emit a single object. `path` is the value written into the "path" field;
 * the file at that path is what we read. The two are the same for direct
 * file entries; for directory entries, the directory is in the config
 * but each emitted entry's path is the joined dir/file.
 */
static int emit_entry(struct attest_emitter *em, const char *path)
{
    /* Try to extract build-id. Fail-soft: empty build_id is the
     * canonical "this isn't an ELF" or "this is a stripped ELF" signal. */
    uint8_t build_id[ELF_BUILD_ID_MAX_BYTES];
    size_t build_id_len = 0;
    int rc = elf_walker_extract_buildid_from_path(path, build_id,
                                                  &build_id_len);
    if (rc != ELF_WALKER_OK) {
        build_id_len = 0;
        if (verbose_enabled()) {
            const char *why =
                (rc == ELF_WALKER_NOT_ELF)    ? "not an ELF"      :
                (rc == ELF_WALKER_NO_BUILDID) ? "stripped"        :
                (rc == ELF_WALKER_IO_ERROR)   ? "io error"        :
                                                "parse error";
            fprintf(stderr, "attest: %s: build_id absent (%s)\n",
                    path, why);
        }
    }

    /* Always compute content sha256 (the dual-hash decision). */
    uint8_t sha[32];
    int too_large = 0;
    int sha_rc = hash_file_content(path, sha, &too_large);
    size_t sha_len = (sha_rc == 0) ? 32 : 0;
    if (sha_rc != 0 && verbose_enabled()) {
        if (too_large) {
            fprintf(stderr, "attest: %s: sha256 skipped (file > %u MB)\n",
                    path, BINARIES_LIST_MAX_FILE_BYTES / (1024u * 1024u));
        } else {
            fprintf(stderr, "attest: %s: sha256 io error: %s\n",
                    path, strerror(errno));
        }
    }

    int erc = em->ops->object_open(em->ctx);
    if (erc < 0) return erc;

    /* Alphabetical key order (JCS): build_id, path, sha256. */
    erc = em->ops->key(em->ctx, "build_id");
    if (erc < 0) return erc;
    erc = em->ops->value_bytes_hex(em->ctx, build_id, build_id_len);
    if (erc < 0) return erc;

    erc = em->ops->key(em->ctx, "path");
    if (erc < 0) return erc;
    erc = em->ops->value_string(em->ctx, path);
    if (erc < 0) return erc;

    erc = em->ops->key(em->ctx, "sha256");
    if (erc < 0) return erc;
    erc = em->ops->value_bytes_hex(em->ctx, sha, sha_len);
    if (erc < 0) return erc;

    return em->ops->object_close(em->ctx);
}

/* ------------------------------------------------------------------ */
/* Filter for scandir — keep regular files, drop "." and ".."         */
/* ------------------------------------------------------------------ */

static int dirent_filter(const struct dirent *e)
{
    if (e->d_name[0] == '.' &&
        (e->d_name[1] == '\0' ||
         (e->d_name[1] == '.' && e->d_name[2] == '\0'))) {
        return 0;
    }
    return 1;
}

/*
 * Walk one directory's entries. Joined "dir/entry" path is built per
 * file, lstat'd, regular-file-only (symlinks/subdirs skipped).
 */
static int emit_directory(struct attest_emitter *em, const char *dir)
{
    struct dirent **entries = NULL;
    int n = scandir(dir, &entries, dirent_filter, alphasort);
    if (n < 0) {
        if (verbose_enabled()) {
            fprintf(stderr, "attest: %s: scandir failed: %s\n",
                    dir, strerror(errno));
        }
        return 0; /* deterministic empty contribution */
    }
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = entries[i]->d_name;
        size_t pl = strlen(dir) + 1 + strlen(name) + 1;
        char *full = malloc(pl);
        if (full == NULL) {
            rc = -1;
            break;
        }
        snprintf(full, pl, "%s/%s", dir, name);

        struct stat st;
        if (lstat(full, &st) != 0) {
            free(full);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            if (verbose_enabled() && S_ISLNK(st.st_mode)) {
                fprintf(stderr, "attest: %s: skipped (symlink, "
                                "v0.5.1 adds lstat-tagged emission)\n",
                        full);
            }
            free(full);
            continue;
        }
        if ((uint64_t)st.st_size > BINARIES_LIST_MAX_FILE_BYTES) {
            if (verbose_enabled()) {
                fprintf(stderr,
                        "attest: %s: skipped (file > %u MB)\n",
                        full,
                        BINARIES_LIST_MAX_FILE_BYTES / (1024u * 1024u));
            }
            free(full);
            continue;
        }
        rc = emit_entry(em, full);
        free(full);
        if (rc < 0) {
            break;
        }
    }
    for (int i = 0; i < n; i++) {
        free(entries[i]);
    }
    free(entries);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Top-level walker                                                    */
/* ------------------------------------------------------------------ */

int attest_adapter_binaries_list(struct attest_emitter *em)
{
    int rc = em->ops->array_open(em->ctx);
    if (rc < 0) return rc;

    const attest_config_t *cfg = attest_config_get();
    if (cfg == NULL || cfg->binaries.n == 0) {
        return em->ops->array_close(em->ctx);
    }

    for (size_t i = 0; i < cfg->binaries.n; i++) {
        const char *path = cfg->binaries.paths[i];
        struct stat st;
        if (lstat(path, &st) != 0) {
            /* E301: configured path not present. Emit deterministic
             * placeholder entry so the diff between bird and FlatSat
             * surfaces the misconfig at the path-level granularity. */
            fprintf(stderr,
                    "attest: %s: configured path not present on this "
                    "rootfs (E301)\n", path);
            int erc = em->ops->object_open(em->ctx);
            if (erc < 0) return erc;
            erc = em->ops->key(em->ctx, "build_id");
            if (erc < 0) return erc;
            erc = em->ops->value_bytes_hex(em->ctx, NULL, 0);
            if (erc < 0) return erc;
            erc = em->ops->key(em->ctx, "path");
            if (erc < 0) return erc;
            erc = em->ops->value_string(em->ctx, path);
            if (erc < 0) return erc;
            erc = em->ops->key(em->ctx, "sha256");
            if (erc < 0) return erc;
            erc = em->ops->value_bytes_hex(em->ctx, NULL, 0);
            if (erc < 0) return erc;
            erc = em->ops->object_close(em->ctx);
            if (erc < 0) return erc;
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            rc = emit_directory(em, path);
            if (rc < 0) {
                return rc;
            }
        } else if (S_ISREG(st.st_mode)) {
            rc = emit_entry(em, path);
            if (rc < 0) {
                return rc;
            }
        } else if (S_ISLNK(st.st_mode)) {
            if (verbose_enabled()) {
                fprintf(stderr, "attest: %s: skipped (symlink, "
                                "v0.5.1 adds lstat-tagged emission)\n",
                        path);
            }
            continue;
        } else {
            if (verbose_enabled()) {
                fprintf(stderr, "attest: %s: skipped (not file/dir)\n",
                        path);
            }
            continue;
        }
    }

    return em->ops->array_close(em->ctx);
}
