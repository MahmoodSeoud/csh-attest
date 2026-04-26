/*
 * csh-attest — read-only attestation APM for libcsp/CSP firmware.
 *
 * The csh APM ABI requires three exports: `apm_init_version` (const int),
 * `libmain(void)` (int), and optionally `libinfo(void)`. The csh loader
 * dlsym's all three; libmain is what runs on apm load.
 *
 * Session 2 contract: a hand-rolled libmain that walks the `slash` ELF
 * section (populated by slash_command(...) macros) and registers each entry
 * via slash_list_add(), resolved at dlopen time against csh's process. This
 * mirrors what upstream libapm_csh::libmain does, minus the param/vmem
 * sections and minus apm_csh's transitive libparam+libcsp dep tree (deferred
 * to a later session). The walker is ~15 lines and gets deleted when apm_csh
 * is properly wired.
 *
 * Layout / responsibilities:
 *   - apm_init_version: ABI handshake (10, current csh master).
 *   - libmain():        register slash commands, then call apm_init().
 *   - apm_init():       startup work hook — heap precheck (4B), session-dir
 *                       tmpfs check (4C), CSP listener spawn. Currently
 *                       delegates to csh_attest_init() for testability.
 *   - libinfo():        APM banner shown by `apm info`.
 *   - hello_cmd():      session-1 liveness command, replaced by attest /
 *                       attest-diff in session 3.
 */

#include "csh_attest.h"

#include <stdio.h>
#include <string.h>

#include "attest.h"
#include "jcs.h"
#include "sign.h"

#ifdef CSH_ATTEST_HAVE_SLASH
#include <slash.h>

static int hello_cmd(struct slash *slash)
{
    (void)slash;
    printf("hello\n");
    return SLASH_SUCCESS;
}
slash_command(hello, hello_cmd, "", "csh-attest scaffold liveness check");

/*
 * `attest --emit`: writes the canonical manifest for the running host to
 * stdout (no signature).
 *
 * `attest --sign <keyfile>`: writes a JCS-canonical signed envelope to
 * stdout:
 *     {"manifest":"<inner-canonical-as-string>","sig":"<hex>"}
 * where <inner-canonical-as-string> is the JCS-canonical manifest
 * re-emitted as a JSON string (so a downstream JSON parser unescapes back
 * to the canonical bytes that the signature was computed over). The
 * envelope itself is canonical too — keys "manifest" < "sig" alphabetically.
 *
 * `--remote` and `--verify` are deferred to later sessions.
 */

/* Local helper — runs attest_emit through a fresh canonical emitter into
 * the caller's buffer. Returns the underlying attest_emit return code. */
static int csh_attest_emit_canonical(struct jcs_buffer *buf)
{
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_canonical_init(&em, &ctx, buf);
    return attest_emit(&em);
}

static int attest_cmd(struct slash *slash)
{
    bool emit = false;
    const char *sign_key_path = NULL;

    /*
     * Hand-rolled arg parsing — only two flags, no need for optparse + its
     * link-time symbols. Accepts: `--emit` (no value), `--sign <keyfile>`
     * (one positional value), or both. Anything else is rejected.
     */
    for (int i = 1; i < slash->argc; i++) {
        const char *arg = slash->argv[i];
        if (strcmp(arg, "--emit") == 0) {
            emit = true;
        } else if (strcmp(arg, "--sign") == 0) {
            if (i + 1 >= slash->argc) {
                fprintf(stderr, "csh-attest: --sign requires a key path\n");
                return SLASH_EUSAGE;
            }
            sign_key_path = slash->argv[++i];
        } else {
            fprintf(stderr, "csh-attest: unknown argument: %s\n", arg);
            return SLASH_EUSAGE;
        }
    }

    if (!emit && sign_key_path == NULL) {
        fprintf(stderr,
                "csh-attest: pass --emit or --sign <keyfile>\n");
        return SLASH_EUSAGE;
    }

    /*
     * Inner canonical manifest. Always produced — both --emit and --sign
     * start here. Signing layers an outer envelope on top.
     */
    struct jcs_buffer inner;
    jcs_buffer_init(&inner);

    int rc = csh_attest_emit_canonical(&inner);
    if (rc != 0) {
        fprintf(stderr, "csh-attest: emit failed (rc=%d)\n", rc);
        jcs_buffer_free(&inner);
        return SLASH_EIO;
    }

    if (sign_key_path == NULL) {
        /* --emit path: just dump the inner canonical bytes. */
        fwrite(inner.data, 1, inner.len, stdout);
        fputc('\n', stdout);
        jcs_buffer_free(&inner);
        return SLASH_SUCCESS;
    }

    /* --sign path. */
    if (attest_sign_init() != ATTEST_SIGN_OK) {
        fprintf(stderr, "csh-attest: E205: libsodium init failed\n");
        jcs_buffer_free(&inner);
        return SLASH_EIO;
    }

    uint8_t secret_key[ATTEST_SIGN_SECRET_KEY_BYTES];
    int load_rc = attest_sign_load_secret_key(sign_key_path, secret_key);
    if (load_rc != ATTEST_SIGN_OK) {
        const char *msg = (load_rc == ATTEST_SIGN_ERR_KEY_PERMS)
            ? "E202: private key file is world/group readable"
            : "E203: private key file malformed or unreadable";
        fprintf(stderr, "csh-attest: %s: %s\n", msg, sign_key_path);
        jcs_buffer_free(&inner);
        return SLASH_EIO;
    }

    uint8_t signature[ATTEST_SIGN_SIGNATURE_BYTES];
    int sign_rc = attest_sign_canonical(inner.data, inner.len, secret_key,
                                        signature);
    /*
     * Wipe the secret key from the stack as soon as we're done with it.
     * libsodium's sodium_memzero would be ideal here; using a manual
     * volatile loop keeps this file's libsodium surface to sign.c only.
     */
    for (size_t i = 0; i < sizeof(secret_key); i++) {
        ((volatile uint8_t *)secret_key)[i] = 0;
    }
    if (sign_rc != ATTEST_SIGN_OK) {
        fprintf(stderr, "csh-attest: E205: signing failed\n");
        jcs_buffer_free(&inner);
        return SLASH_EIO;
    }

    /*
     * Build the outer canonical envelope. The inner canonical bytes are
     * passed to value_string as a NUL-terminated C string — safe because
     * canonical JSON never contains 0x00 bytes.
     */
    if (jcs_buffer_append_nul(&inner) != 0) {
        fprintf(stderr, "csh-attest: E204: out of memory\n");
        jcs_buffer_free(&inner);
        return SLASH_EIO;
    }

    struct jcs_buffer outer;
    jcs_buffer_init(&outer);
    struct jcs_canonical_ctx outer_ctx;
    struct attest_emitter outer_em;
    jcs_canonical_init(&outer_em, &outer_ctx, &outer);

    int env_rc = outer_em.ops->object_open(outer_em.ctx);
    if (env_rc == 0) {
        env_rc = outer_em.ops->key(outer_em.ctx, "manifest");
    }
    if (env_rc == 0) {
        env_rc = outer_em.ops->value_string(outer_em.ctx,
                                            (const char *)inner.data);
    }
    if (env_rc == 0) {
        env_rc = outer_em.ops->key(outer_em.ctx, "sig");
    }
    if (env_rc == 0) {
        env_rc = outer_em.ops->value_bytes_hex(outer_em.ctx, signature,
                                               sizeof(signature));
    }
    if (env_rc == 0) {
        env_rc = outer_em.ops->object_close(outer_em.ctx);
    }

    if (env_rc == 0) {
        fwrite(outer.data, 1, outer.len, stdout);
        fputc('\n', stdout);
    } else {
        fprintf(stderr, "csh-attest: E204: envelope build failed\n");
    }

    jcs_buffer_free(&outer);
    jcs_buffer_free(&inner);

    return env_rc == 0 ? SLASH_SUCCESS : SLASH_EIO;
}
slash_command(attest, attest_cmd, "--emit | --sign <keyfile>",
              "Emit attestation manifest, optionally signed");
#endif /* CSH_ATTEST_HAVE_SLASH */

/* csh APM ABI handshake. v10 matches current csh master (see
 * spaceinventor/libapm_csh include/apm/csh_api.h:30). */
const int apm_init_version = 10;

/*
 * APM banner shown by `apm info`. csh's loader dlsym's this; missing is
 * tolerated, present overrides the default banner.
 */
void libinfo(void);
void libinfo(void)
{
    printf("csh-attest 0.0.1 — read-only attestation APM (scaffold)\n");
}

/*
 * apm_init hook called by libmain after slash command registration.
 * Returning non-zero aborts the load (csh exit(1)).
 */
int apm_init(void);
int apm_init(void)
{
    return csh_attest_init();
}

#ifdef CSH_ATTEST_HAVE_SLASH
/*
 * slash_list_add is exported by csh (which links slash). We declare it weak
 * here so the cmocka unit test (which does not link slash) still compiles —
 * libmain itself is not exercised by tests.
 */
__attribute__((weak)) extern int slash_list_add(struct slash_command *cmd);
#endif

int libmain(void);
int libmain(void)
{
#ifdef CSH_ATTEST_HAVE_SLASH
    /*
     * The slash_command(...) macros emit `const struct slash_command` entries
     * into the ELF section "slash". The linker provides __start_slash and
     * __stop_slash bracket symbols; weak so a slash-less build still resolves.
     */
    extern struct slash_command __start_slash
        __attribute__((visibility("hidden"), weak));
    extern struct slash_command __stop_slash
        __attribute__((visibility("hidden"), weak));

    if (slash_list_add != NULL && (&__start_slash != &__stop_slash)) {
        for (struct slash_command *cmd = &__start_slash; cmd < &__stop_slash;
             cmd++) {
            int res = slash_list_add(cmd);
            if (res < 0) {
                fprintf(stderr,
                        "csh-attest: slash_list_add failed for \"%s\" (%d)\n",
                        cmd->name, res);
                return res;
            }
        }
    }
#endif /* CSH_ATTEST_HAVE_SLASH */

    return apm_init();
}

int csh_attest_init(void)
{
    return 0;
}
