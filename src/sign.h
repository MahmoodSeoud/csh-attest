#pragma once

/*
 * Ed25519 signing + verification — thin wrapper over libsodium.
 *
 * The signed data is the JCS-canonical manifest bytes from jcs_buffer (see
 * jcs.h). This wrapper does NOT canonicalize input; the caller is expected
 * to have canonicalized first. That separation keeps the signing layer
 * agnostic of any future canonicalization changes.
 *
 * Per design doc 1C: ground-side signing only in v1. Persistent per-mission
 * keypair stored in the operator's secret-management; pubkey published in
 * the mission git repo at `keys/<mission-id>.pub`. Bird-side signing
 * deferred to v2.
 *
 * Failure modes per design doc 2D (E2xx range):
 *   E202 — private key file is world-readable; refuse to sign.
 *   E201 — verification failed (tampered bytes or wrong key).
 *   E203 — key file malformed.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes per libsodium / Ed25519. Hard-coded so callers don't need
 * <sodium.h> just to allocate buffers. */
#define ATTEST_SIGN_PUBLIC_KEY_BYTES   32u
#define ATTEST_SIGN_SECRET_KEY_BYTES   64u
#define ATTEST_SIGN_SIGNATURE_BYTES    64u

/* Error codes. Internal — slash command layer maps to E2xx + stderr. */
typedef enum {
    ATTEST_SIGN_OK = 0,
    ATTEST_SIGN_ERR_KEY_PERMS = -202,    /* world-readable privkey */
    ATTEST_SIGN_ERR_VERIFY    = -201,    /* signature mismatch */
    ATTEST_SIGN_ERR_KEY_FORMAT = -203,   /* malformed key file */
    ATTEST_SIGN_ERR_IO        = -204,    /* read / write failure */
    ATTEST_SIGN_ERR_SODIUM    = -205,    /* libsodium init failure */
} attest_sign_status_t;

/*
 * Initialize libsodium. Idempotent. Must be called before any sign/verify.
 * Returns 0 on success, ATTEST_SIGN_ERR_SODIUM on failure.
 */
int attest_sign_init(void);

/*
 * Load a 64-byte Ed25519 secret key from a file. The file must hold exactly
 * 64 raw bytes (the libsodium combined seed+public format) and must NOT be
 * world- or group-readable (refuses with ATTEST_SIGN_ERR_KEY_PERMS — 0o600
 * or stricter required).
 *
 * Output buffer must be at least ATTEST_SIGN_SECRET_KEY_BYTES bytes.
 */
int attest_sign_load_secret_key(const char *path, uint8_t *out_secret);

/*
 * Load a 32-byte Ed25519 public key from a file. Public keys do NOT have
 * the world-readable check — by definition they are publishable.
 *
 * Output buffer must be at least ATTEST_SIGN_PUBLIC_KEY_BYTES bytes.
 */
int attest_sign_load_public_key(const char *path, uint8_t *out_public);

/*
 * Detached Ed25519 signature over `bytes`. Output buffer must be at least
 * ATTEST_SIGN_SIGNATURE_BYTES bytes.
 *
 * Caller MUST hand canonical bytes — no canonicalization happens here.
 */
int attest_sign_canonical(const uint8_t *bytes, size_t len,
                          const uint8_t *secret_key,
                          uint8_t *out_signature);

/*
 * Verify a detached Ed25519 signature over `bytes`. Returns ATTEST_SIGN_OK
 * on valid signature, ATTEST_SIGN_ERR_VERIFY on tamper / wrong key.
 */
int attest_verify_canonical(const uint8_t *bytes, size_t len,
                            const uint8_t *signature,
                            const uint8_t *public_key);

/*
 * Generate an Ed25519 keypair into the caller's buffers. Used by both
 * unit tests and the `attest --keygen <prefix>` slash command (see
 * csh_attest.c:attest_keygen_run). Operators in production may also
 * provision keys with external tooling (sodium-cli, openssl with the
 * right plugin, an HSM); the on-disk format is the libsodium combined
 * seed+public 64-byte secret + 32-byte public, so any tool that emits
 * those is interchangeable with --keygen.
 */
int attest_sign_keypair(uint8_t *out_public, uint8_t *out_secret);

#ifdef __cplusplus
}
#endif
