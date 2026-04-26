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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "attest.h"
#include "diff.h"
#include "diff_render.h"
#include "jcs.h"
#include "jcs_parse.h"
#include "sign.h"

#ifdef __linux__
/* CSP transport for `attest --remote`. Linux-only — libcsp's POSIX driver
 * doesn't compile on macOS clang under -Werror. macOS dev path keeps the
 * non-CSP build; the remote dispatch below is gated on the same macro. */
#include "csp_client.h"
#include "csp_server.h"
#endif

/*
 * File loader for attest-diff. Reads `path` into a heap buffer; caller
 * frees. 1 MB sanity cap is well above the design doc's 200 KB hard cap
 * for an individual manifest, leaving headroom for an envelope that wraps
 * one in a string field. Returns 0 on success, -1 on any I/O error.
 */
static int load_file(const char *path, uint8_t **out_bytes, size_t *out_len,
                     FILE *err)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(err, "csh-attest: E001: cannot open: %s\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        fprintf(err, "csh-attest: E001: seek failed: %s\n", path);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        fprintf(err, "csh-attest: E001: tell failed: %s\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        fprintf(err, "csh-attest: E001: rewind failed: %s\n", path);
        return -1;
    }
    if (sz > (long)(1024 * 1024)) {
        fclose(f);
        fprintf(err,
                "csh-attest: E105: %s exceeds 1 MB sanity cap (%ld bytes)\n",
                path, sz);
        return -1;
    }
    if (sz == 0) {
        fclose(f);
        *out_bytes = NULL;
        *out_len = 0;
        return 0;
    }
    uint8_t *buf = malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        fprintf(err, "csh-attest: E901: out of memory loading %s\n", path);
        return -1;
    }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (r != (size_t)sz) {
        free(buf);
        fprintf(err, "csh-attest: E001: short read: %s\n", path);
        return -1;
    }
    *out_bytes = buf;
    *out_len = (size_t)sz;
    return 0;
}

/*
 * Decode one lowercase-hex byte (two chars at *s) into *out. Strict —
 * uppercase or non-hex chars are rejected so callers can rely on a parsed
 * envelope sig being byte-identical to the one the canonical emitter wrote.
 * Returns 0 on success, -1 on any non-[0-9a-f] character.
 */
static int hex_byte(const char *s, uint8_t *out)
{
    uint8_t v = 0;
    for (int i = 0; i < 2; i++) {
        char c = s[i];
        v = (uint8_t)(v << 4);
        if (c >= '0' && c <= '9') {
            v = (uint8_t)(v | (uint8_t)(c - '0'));
        } else if (c >= 'a' && c <= 'f') {
            v = (uint8_t)(v | (uint8_t)(c - 'a' + 10));
        } else {
            return -1;
        }
    }
    *out = v;
    return 0;
}

/*
 * Look up a top-level member by exact key match. Linear scan — the v1
 * envelope has 2 members so this stays O(n) trivially. Returns NULL if
 * absent. The parser already enforces sorted unique keys.
 */
static const struct jcsp_value *envelope_get(const struct jcsp_value *env,
                                             const char *key)
{
    for (size_t i = 0; i < env->u.object.n; i++) {
        if (strcmp(env->u.object.members[i].key, key) == 0) {
            return &env->u.object.members[i].value;
        }
    }
    return NULL;
}

int attest_verify_run(int argc, char **argv, FILE *out, FILE *err)
{
    (void)out; /* verify is silent on success — only stderr on failure */

    if (argc != 3) {
        fprintf(err,
                "csh-attest: usage: "
                "attest --verify <pubkey-file> <signed.json>\n");
        return 2;
    }
    const char *pubkey_path = argv[1];
    const char *signed_path = argv[2];

    if (attest_sign_init() != ATTEST_SIGN_OK) {
        fprintf(err, "csh-attest: E205: libsodium init failed\n");
        return 2;
    }

    uint8_t pubkey[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    int load_rc = attest_sign_load_public_key(pubkey_path, pubkey);
    if (load_rc != ATTEST_SIGN_OK) {
        fprintf(err,
                "csh-attest: E203: cannot load public key: %s\n", pubkey_path);
        return 2;
    }

    uint8_t *bytes = NULL;
    size_t len = 0;
    struct jcsp_value env;
    memset(&env, 0, sizeof(env));
    int rc = 2;

    if (load_file(signed_path, &bytes, &len, err) != 0) {
        goto cleanup;
    }
    if (jcsp_parse(bytes, len, &env) != 0) {
        fprintf(err,
                "csh-attest: E001: %s is not JCS-canonical JSON\n",
                signed_path);
        goto cleanup;
    }
    if (env.type != JCSP_OBJECT) {
        fprintf(err,
                "csh-attest: E001: %s envelope must be a JSON object\n",
                signed_path);
        goto cleanup;
    }

    const struct jcsp_value *manifest = envelope_get(&env, "manifest");
    const struct jcsp_value *sig = envelope_get(&env, "sig");
    if (manifest == NULL || sig == NULL ||
        manifest->type != JCSP_STRING || sig->type != JCSP_STRING) {
        fprintf(err,
                "csh-attest: E001: %s missing or malformed "
                "\"manifest\"/\"sig\" fields\n",
                signed_path);
        goto cleanup;
    }
    if (sig->u.string.len != ATTEST_SIGN_SIGNATURE_BYTES * 2) {
        fprintf(err,
                "csh-attest: E001: signature length %zu, expected %u hex chars\n",
                sig->u.string.len, ATTEST_SIGN_SIGNATURE_BYTES * 2);
        goto cleanup;
    }

    uint8_t signature[ATTEST_SIGN_SIGNATURE_BYTES];
    for (size_t i = 0; i < ATTEST_SIGN_SIGNATURE_BYTES; i++) {
        if (hex_byte(sig->u.string.bytes + i * 2, &signature[i]) != 0) {
            fprintf(err,
                    "csh-attest: E001: signature contains non-hex character\n");
            goto cleanup;
        }
    }

    int verify_rc = attest_verify_canonical(
        (const uint8_t *)manifest->u.string.bytes, manifest->u.string.len,
        signature, pubkey);
    if (verify_rc == ATTEST_SIGN_OK) {
        rc = 0;
    } else {
        fprintf(err,
                "csh-attest: E201: signature verification failed for %s\n",
                signed_path);
        rc = 1;
    }

cleanup:
    jcsp_value_free(&env);
    free(bytes);
    return rc;
}

int attest_diff_run(int argc, char **argv, FILE *out, FILE *err)
{
    bool json_mode = false;
    bool no_color = false;
    const char *lhs_path = NULL;
    const char *rhs_path = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--json") == 0) {
            json_mode = true;
        } else if (strcmp(a, "--no-color") == 0) {
            no_color = true;
        } else if (a[0] == '-') {
            fprintf(err, "csh-attest: E901: unknown flag: %s\n", a);
            return 2;
        } else if (lhs_path == NULL) {
            lhs_path = a;
        } else if (rhs_path == NULL) {
            rhs_path = a;
        } else {
            fprintf(err,
                    "csh-attest: E901: unexpected positional argument: %s\n",
                    a);
            return 2;
        }
    }
    if (lhs_path == NULL || rhs_path == NULL) {
        fprintf(err,
                "csh-attest: usage: "
                "attest-diff [--json] [--no-color] <lhs.json> <rhs.json>\n");
        return 2;
    }

    uint8_t *lhs_bytes = NULL;
    uint8_t *rhs_bytes = NULL;
    size_t lhs_len = 0;
    size_t rhs_len = 0;
    struct jcsp_value lhs_v;
    struct jcsp_value rhs_v;
    memset(&lhs_v, 0, sizeof(lhs_v));
    memset(&rhs_v, 0, sizeof(rhs_v));
    struct diff_result result;
    memset(&result, 0, sizeof(result));
    int rc = 2;

    if (load_file(lhs_path, &lhs_bytes, &lhs_len, err) != 0) {
        goto cleanup;
    }
    if (load_file(rhs_path, &rhs_bytes, &rhs_len, err) != 0) {
        goto cleanup;
    }

    if (jcsp_parse(lhs_bytes, lhs_len, &lhs_v) != 0) {
        fprintf(err, "csh-attest: E001: %s is not JCS-canonical JSON\n",
                lhs_path);
        goto cleanup;
    }
    if (jcsp_parse(rhs_bytes, rhs_len, &rhs_v) != 0) {
        fprintf(err, "csh-attest: E001: %s is not JCS-canonical JSON\n",
                rhs_path);
        goto cleanup;
    }
    if (lhs_v.type != JCSP_OBJECT || rhs_v.type != JCSP_OBJECT) {
        fprintf(err,
                "csh-attest: E001: both inputs must be top-level objects\n");
        goto cleanup;
    }

    if (attest_diff(&lhs_v, &rhs_v, &result) != 0) {
        fprintf(err, "csh-attest: E001: diff failed\n");
        goto cleanup;
    }

    diff_render_opts_t opts = {
        .json_mode = json_mode,
        .color = diff_should_color(json_mode, no_color, out),
    };
    if (diff_render(out, &result, &opts) != 0) {
        fprintf(err, "csh-attest: E901: render failed\n");
        goto cleanup;
    }

    rc = diff_has_drift(&result) ? 1 : 0;

cleanup:
    diff_result_free(&result);
    jcsp_value_free(&lhs_v);
    jcsp_value_free(&rhs_v);
    free(lhs_bytes);
    free(rhs_bytes);
    return rc;
}

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
 * `attest-diff <lhs.json> <rhs.json> [--json] [--no-color]`. The function
 * body is just a forwarder — attest_diff_run does the real work and is
 * unit-tested directly. csh propagates this return value as the exit
 * code in `csh -c "..."` mode, so the design-doc 0/1/2 contract is met.
 */
static int attest_diff_cmd(struct slash *slash)
{
    return attest_diff_run(slash->argc, slash->argv, stdout, stderr);
}
slash_command_named(attest_diff, "attest-diff", attest_diff_cmd,
                    "[--json] [--no-color] <lhs.json> <rhs.json>",
                    "Compare two attestation manifests; "
                    "exit 0=parity 1=drift 2=error");

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
    const char *verify_pubkey_path = NULL;
    const char *verify_signed_path = NULL;
    const char *remote_node = NULL;

    /*
     * Hand-rolled arg parsing — four subcommand flags, no need for optparse
     * + its link-time symbols. Accepts:
     *   --emit                          (no value)
     *   --sign <keyfile>                (one positional value)
     *   --verify <pubkey> <signed.json> (two positional values)
     *   --remote <node>                 (one positional value)
     * Anything else is rejected. --verify and --remote are each exclusive
     * with everything else; --emit and --sign coexist (--sign implies emit).
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
        } else if (strcmp(arg, "--verify") == 0) {
            if (i + 2 >= slash->argc) {
                fprintf(stderr,
                        "csh-attest: --verify requires "
                        "<pubkey-file> <signed.json>\n");
                return SLASH_EUSAGE;
            }
            verify_pubkey_path = slash->argv[++i];
            verify_signed_path = slash->argv[++i];
        } else if (strcmp(arg, "--remote") == 0) {
            if (i + 1 >= slash->argc) {
                fprintf(stderr,
                        "csh-attest: --remote requires <node>\n");
                return SLASH_EUSAGE;
            }
            remote_node = slash->argv[++i];
        } else {
            fprintf(stderr, "csh-attest: unknown argument: %s\n", arg);
            return SLASH_EUSAGE;
        }
    }

    if (verify_pubkey_path != NULL) {
        if (emit || sign_key_path != NULL || remote_node != NULL) {
            fprintf(stderr,
                    "csh-attest: --verify is exclusive with "
                    "--emit/--sign/--remote\n");
            return SLASH_EUSAGE;
        }
        char *vargv[] = {
            (char *)"attest --verify",
            (char *)verify_pubkey_path,
            (char *)verify_signed_path,
        };
        /* Driver returns 0/1/2 shell-style. csh propagates this verbatim
         * via `csh -c`, so the design-doc 0=valid / 1=invalid / 2=error
         * contract reaches the caller. */
        return attest_verify_run(3, vargv, stdout, stderr);
    }

    if (remote_node != NULL) {
        if (emit || sign_key_path != NULL) {
            fprintf(stderr,
                    "csh-attest: --remote is exclusive with --emit/--sign\n");
            return SLASH_EUSAGE;
        }
#ifdef __linux__
        char *rargv[] = {(char *)"attest --remote", (char *)remote_node};
        return attest_remote_run(2, rargv, stdout, stderr);
#else
        fprintf(stderr,
                "csh-attest: E101: --remote requires the libcsp transport "
                "(Linux build only)\n");
        return SLASH_EIO;
#endif
    }

    if (!emit && sign_key_path == NULL) {
        fprintf(stderr,
                "csh-attest: pass --emit, --sign <keyfile>, "
                "--verify <pubkey> <signed.json>, "
                "or --remote <node>\n");
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
slash_command(attest, attest_cmd,
              "--emit | --sign <keyfile> | --verify <pubkey> <signed.json> "
              "| --remote <node>",
              "Emit, sign, verify, or fetch a remote attestation manifest");
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
    printf("csh-attest 0.1.0 — read-only attestation APM\n");
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
#ifdef __linux__
    /*
     * Spawn the bird-side CSP listener thread that answers `attest --remote`
     * requests. Pre-condition: csh has called csp_init() + brought up the
     * router. Production csh does this; standalone unit tests that exercise
     * apm_init() must do the same setup before calling us (see
     * tests/test_init.c::main_setup_csp).
     *
     * Returns non-zero on pthread_create failure — caller (libmain → csh)
     * treats that as fatal and aborts the load, which is the right call:
     * a half-initialized APM that registered slash commands but can't serve
     * --remote is worse than no APM at all.
     */
    if (attest_csp_server_start() != 0) {
        return -1;
    }
#endif
    return 0;
}
