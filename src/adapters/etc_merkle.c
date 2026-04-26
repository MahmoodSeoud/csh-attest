/*
 * etc.merkle adapter implementation. See etc_merkle.h for the algorithm.
 *
 * Two functions:
 *   - compute_etc_merkle: testable helper, takes any path list.
 *   - attest_adapter_etc_merkle: production wrapper with the v1 allowlist.
 *
 * Sodium init: libsodium's hashing API (crypto_hash_sha256_*) is documented
 * as safe to call without sodium_init(), but we call it defensively to keep
 * the contract uniform across compute_etc_merkle and the sign.c path.
 */

#include "etc_merkle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "attest.h"

/* ------------------------------------------------------------------ */
/* Path-list sort.                                                    */
/* ------------------------------------------------------------------ */

static int path_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ------------------------------------------------------------------ */
/* SHA-256 streaming over a file's content. File-missing → empty.     */
/* Buffer size 4 KB — fits the typical /etc/hostname or os-release    */
/* in 1-2 reads while not blowing the stack.                          */
/* ------------------------------------------------------------------ */

static int hash_file_content(const char *path, uint8_t out[32])
{
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);

    FILE *f = fopen(path, "rb");
    if (f != NULL) {
        uint8_t buf[4096];
        size_t r;
        while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
            crypto_hash_sha256_update(&st, buf, r);
        }
        int err = ferror(f);
        fclose(f);
        if (err) {
            return -1;
        }
    }
    /* If fopen failed (ENOENT / EACCES / etc.) the state is unchanged —
     * crypto_hash_sha256_final on an init'd-but-not-updated state yields
     * SHA256(""), the canonical "no content" hash. */
    crypto_hash_sha256_final(&st, out);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Compute the root.                                                  */
/* ------------------------------------------------------------------ */

int compute_etc_merkle(const char * const *paths, size_t n,
                       uint8_t out_hash[ETC_MERKLE_HASH_BYTES])
{
    if (sodium_init() < 0) {
        return -1;
    }
    if (out_hash == NULL) {
        return -1;
    }
    if (n == 0) {
        /* No paths: root is SHA256(""). Deterministic, semantically
         * "nothing was hashed". Tests can assert this directly. paths
         * may be NULL here — n==0 short-circuits before we dereference. */
        crypto_hash_sha256(out_hash, NULL, 0);
        return 0;
    }
    if (paths == NULL) {
        return -1;
    }

    /* Local sorted copy — paths come in canonical-allowlist order from the
     * production adapter, but the helper is robust against any input. */
    const char **sorted = malloc(n * sizeof(*sorted));
    if (sorted == NULL) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        sorted[i] = paths[i];
    }
    qsort(sorted, n, sizeof(*sorted), path_cmp);

    crypto_hash_sha256_state outer;
    crypto_hash_sha256_init(&outer);

    int rc = 0;
    for (size_t i = 0; i < n; i++) {
        const char *p = sorted[i];
        uint8_t path_hash[32];
        crypto_hash_sha256(path_hash, (const uint8_t *)p, strlen(p));

        uint8_t content_hash[32];
        if (hash_file_content(p, content_hash) < 0) {
            rc = -1;
            goto cleanup;
        }

        crypto_hash_sha256_update(&outer, path_hash, sizeof(path_hash));
        crypto_hash_sha256_update(&outer, content_hash, sizeof(content_hash));
    }

    crypto_hash_sha256_final(&outer, out_hash);

cleanup:
    free(sorted);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Production adapter — v1 allowlist.                                 */
/*                                                                    */
/* Files chosen for stability + universal presence on Linux:          */
/*   /etc/hostname      — bird identity (DIFFERS flatsat vs bird; that*/
/*                        is intentional — surfacing the difference is*/
/*                        diagnostic value).                          */
/*   /etc/os-release    — distro + version identity.                  */
/*                                                                    */
/* On macOS dev neither file is guaranteed to exist; helper treats    */
/* missing files as empty content so the merkle is still deterministic*/
/* (just not particularly useful as attestation).                     */
/*                                                                    */
/* Adding paths to the allowlist is a manifest schema change because  */
/* the merkle root for unchanged content also changes.                */
/* ------------------------------------------------------------------ */

int attest_adapter_etc_merkle(struct attest_emitter *em)
{
    static const char * const allowlist[] = {
        "/etc/hostname",
        "/etc/os-release",
    };
    static const size_t n = sizeof(allowlist) / sizeof(allowlist[0]);

    uint8_t hash[ETC_MERKLE_HASH_BYTES];
    int rc = compute_etc_merkle(allowlist, n, hash);
    if (rc < 0) {
        return rc;
    }
    return em->ops->value_bytes_hex(em->ctx, hash, sizeof(hash));
}
