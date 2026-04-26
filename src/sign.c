/*
 * Ed25519 sign / verify wrapper. Pure thin layer over libsodium —
 * concentrates the libsodium include + version-handshake to one
 * translation unit so the rest of the codebase stays sodium-agnostic.
 *
 * O_CLOEXEC requires _GNU_SOURCE on glibc/musl; set project-wide for
 * Linux in meson.build (this file just consumes it).
 */

#include "sign.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

/*
 * Static-assert the libsodium constants match our public ones. If
 * libsodium ever changes these (it won't, they are protocol-bound) we want
 * a compile-time failure rather than silent buffer over/under-runs at the
 * caller.
 */
_Static_assert(ATTEST_SIGN_PUBLIC_KEY_BYTES == crypto_sign_PUBLICKEYBYTES,
               "Ed25519 public-key size must be 32 bytes");
_Static_assert(ATTEST_SIGN_SECRET_KEY_BYTES == crypto_sign_SECRETKEYBYTES,
               "Ed25519 secret-key size must be 64 bytes");
_Static_assert(ATTEST_SIGN_SIGNATURE_BYTES == crypto_sign_BYTES,
               "Ed25519 signature size must be 64 bytes");

int attest_sign_init(void)
{
    /*
     * sodium_init() is idempotent and thread-safe per upstream docs:
     * returns 0 on first successful call, 1 on subsequent calls, -1 on
     * failure. Treat both 0 and 1 as success.
     */
    int rc = sodium_init();
    if (rc < 0) {
        return ATTEST_SIGN_ERR_SODIUM;
    }
    return ATTEST_SIGN_OK;
}

/*
 * Load a fixed-size raw key from disk. Used for both public and secret
 * keys; the world-readable check is gated by `enforce_perms`.
 */
static int load_raw_key(const char *path, uint8_t *out, size_t expected_len,
                        bool enforce_perms)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return ATTEST_SIGN_ERR_IO;
    }

    if (enforce_perms) {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            close(fd);
            return ATTEST_SIGN_ERR_IO;
        }
        /* Refuse if any group/world bit is set. 0o077 = group + world rwx. */
        if ((st.st_mode & 0077) != 0) {
            close(fd);
            return ATTEST_SIGN_ERR_KEY_PERMS;
        }
    }

    size_t read_total = 0;
    while (read_total < expected_len) {
        ssize_t n = read(fd, out + read_total, expected_len - read_total);
        if (n <= 0) {
            close(fd);
            return ATTEST_SIGN_ERR_KEY_FORMAT;
        }
        read_total += (size_t)n;
    }

    /* Reject keys that are LONGER than expected — partial reads of huge
     * key files would otherwise pass silently. */
    uint8_t tail;
    ssize_t extra = read(fd, &tail, 1);
    close(fd);
    if (extra != 0) {
        /*
         * `extra > 0` ⇒ file longer than expected. `extra < 0` ⇒ read error
         * after a successful body read; treat as malformed (we've already
         * got the bytes we needed but cannot verify the file ends cleanly).
         */
        return ATTEST_SIGN_ERR_KEY_FORMAT;
    }
    return ATTEST_SIGN_OK;
}

int attest_sign_load_secret_key(const char *path, uint8_t *out_secret)
{
    return load_raw_key(path, out_secret, ATTEST_SIGN_SECRET_KEY_BYTES,
                        true);
}

int attest_sign_load_public_key(const char *path, uint8_t *out_public)
{
    return load_raw_key(path, out_public, ATTEST_SIGN_PUBLIC_KEY_BYTES,
                        false);
}

int attest_sign_canonical(const uint8_t *bytes, size_t len,
                          const uint8_t *secret_key, uint8_t *out_signature)
{
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(out_signature, &sig_len, bytes, len,
                             secret_key) != 0) {
        return ATTEST_SIGN_ERR_SODIUM;
    }
    if (sig_len != ATTEST_SIGN_SIGNATURE_BYTES) {
        return ATTEST_SIGN_ERR_SODIUM;
    }
    return ATTEST_SIGN_OK;
}

int attest_verify_canonical(const uint8_t *bytes, size_t len,
                            const uint8_t *signature,
                            const uint8_t *public_key)
{
    if (crypto_sign_verify_detached(signature, bytes, len, public_key) != 0) {
        return ATTEST_SIGN_ERR_VERIFY;
    }
    return ATTEST_SIGN_OK;
}

int attest_sign_keypair(uint8_t *out_public, uint8_t *out_secret)
{
    if (crypto_sign_keypair(out_public, out_secret) != 0) {
        return ATTEST_SIGN_ERR_SODIUM;
    }
    return ATTEST_SIGN_OK;
}
