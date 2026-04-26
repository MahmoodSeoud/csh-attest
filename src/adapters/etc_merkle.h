#pragma once

/*
 * etc.merkle adapter — SHA-256 root over an allowlist of /etc paths.
 *
 * Algorithm (v1, simple):
 *   1. Sort the path list lexicographically.
 *   2. For each path:
 *        path_hash    = SHA256(path_string_bytes)
 *        content_hash = SHA256(file_content)   (empty if file is missing)
 *   3. Root = SHA256( path_hash[0] || content_hash[0]
 *                   || path_hash[1] || content_hash[1] || ... )
 *
 * Why hash the path separately: prevents a content-only collision attack
 * where two different (path, content) pairs that XOR to the same bytes
 * would otherwise land identically in the outer hash. Also makes "file
 * missing" structurally visible (the path slot is always present).
 *
 * Why this isn't a "real" Merkle tree: with v1 allowlist sizes (2-3 paths)
 * a binary tree adds no security and complicates auditing. The flat
 * concatenation is the simplest deterministic root that still hashes
 * paths and contents separately.
 *
 * The helper is testable — pass any path list, including paths under a
 * temp dir. The production adapter wraps with the v1 allowlist below.
 *
 * Per design doc 1F: etc.merkle has a 32-byte size budget (root only).
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETC_MERKLE_HASH_BYTES 32u

/*
 * Compute the merkle root over `paths`. Output is exactly
 * ETC_MERKLE_HASH_BYTES (32) bytes; caller provides storage.
 *
 * The list is sorted internally, so callers don't have to pre-sort. Paths
 * are NUL-terminated strings; missing files are treated as empty content
 * (their slot still contributes path_hash + SHA256("")).
 *
 * Returns 0 on success, -1 on libsodium init failure or allocation
 * failure. I/O errors mid-read are propagated as -1.
 */
int compute_etc_merkle(const char * const *paths, size_t n,
                       uint8_t out_hash[ETC_MERKLE_HASH_BYTES]);

#ifdef __cplusplus
}
#endif
