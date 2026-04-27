/*
 * csh-attest — read-only attestation APM for libcsp/CSP firmware.
 *
 * The csh APM ABI requires three exports: `apm_init_version` (const int),
 * `libmain(void)` (int), and optionally `libinfo(void)`. The csh loader
 * dlsym's all three; libmain is what runs on apm load.
 *
 * Linux: `apm_init_version` and `libmain` come from upstream libapm_csh
 * (subprojects/apm_csh.wrap, linked via .as_link_whole()). Its libmain
 * walks the `slash` / `param` / `vmem` ELF sections and finally calls our
 * weak `apm_init()` hook. We only have a `slash` section, so the param /
 * vmem walks short-circuit at runtime via the upstream's
 * `&__start_X != &__stop_X` guards.
 *
 * macOS dev builds skip libcsp + libapm_csh (libcsp's POSIX driver doesn't
 * compile under darwin clang -Werror). For compile-check parity we provide
 * a minimal `apm_init_version` + `libmain` shell at the bottom of this file
 * gated `#ifndef __linux__`. macOS isn't a load target, so the shell never
 * runs in production.
 *
 * Layout / responsibilities:
 *   - apm_init():       startup work hook — heap precheck (4B), session-dir
 *                       tmpfs check (4C), CSP listener spawn. Currently
 *                       delegates to csh_attest_init() for testability.
 *                       Strong def here overrides apm_csh's weak hidden
 *                       forward decl in <apm/apm.h>.
 *   - libinfo():        APM banner shown by `apm info`. Not part of the
 *                       upstream apm_csh surface — csh dlsym's it directly.
 *   - hello_cmd():      session-1 liveness command, kept alongside attest /
 *                       attest-diff for `apm info` style smoke tests.
 */

#include "csh_attest.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
        fprintf(err,
                "csh-attest: E001: cannot open: %s\n"
                "  cause: file does not exist or is not readable by this user\n"
                "  fix:   check the path; if the file is owned by another user, "
                "run with the right uid or chmod\n",
                path);
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
                "csh-attest: E203: cannot load public key: %s\n"
                "  cause: file is missing, unreadable, or not exactly %u "
                "raw bytes\n"
                "  fix:   keys/<name>.pub must be the 32-byte Ed25519 public "
                "half of the keypair you signed with\n",
                pubkey_path, ATTEST_SIGN_PUBLIC_KEY_BYTES);
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

/*
 * Render the `attest --help` block. Plain stdio — no slash, no csh, no
 * libsodium. Lives outside CSH_ATTEST_HAVE_SLASH so it's reachable from
 * the unit tests on macOS dev builds where the slash surface is gated
 * off. The text is the source of truth for the human-readable summary;
 * the README has the long-form reference.
 */
void attest_print_help(FILE *out)
{
    fprintf(out,
"attest \xe2\x80\x94 read-only firmware attestation APM (csh-attest %s)\n"
"\n"
"usage:\n"
"  attest --emit                            "
"emit JCS-canonical manifest to stdout\n"
"  attest --sign <keyfile>                  "
"emit signed envelope to stdout\n"
"  attest --verify <pubkey> <signed.json>   "
"verify a signed manifest\n"
"  attest --remote <node>                   "
"fetch a manifest from a remote bird (Linux only)\n"
"  attest --keygen <prefix>                 "
"write a fresh Ed25519 keypair to <prefix>.pub + <prefix>.sec\n"
"  attest --help | -h                       "
"this message\n"
"  attest-diff [--json] [--no-color] <lhs.json> <rhs.json>\n"
"                                           "
"structural diff over two manifests\n"
"\n"
"env vars:\n"
"  ATTEST_CSP_PORT          CSP port for --remote (1..16, default 13)\n"
"  ATTEST_CSP_TIMEOUT_MS    per-packet read timeout "
"(100..60000 ms, default 5000)\n"
"\n"
"exit codes:\n"
"  0  success / signature valid / parity\n"
"  1  drift / signature invalid\n"
"  2  usage / file / parse error\n"
"  3  CSP transport error (E101..E105)\n"
"\n"
"See README.md \"Error codes\" for the full Exxx reference.\n",
            CSH_ATTEST_VERSION);
}

#ifdef CSH_ATTEST_HAVE_SLASH
#include <slash/slash.h>

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

/*
 * Write `len` bytes to <prefix><suffix> with the given mode. O_EXCL so we
 * never silently overwrite an existing key (operator must rotate
 * deliberately). Returns 0 on success, an errno-style code on failure (the
 * caller renders the user-facing E2xx message).
 */
static int write_key_file(const char *prefix, const char *suffix,
                          mode_t mode, const uint8_t *bytes, size_t len)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s%s", prefix, suffix);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        return -1;
    }
    ssize_t w = write(fd, bytes, len);
    int rc = (w == (ssize_t)len) ? 0 : -1;
    if (close(fd) != 0) {
        rc = -1;
    }
    return rc;
}

/*
 * Generate a fresh Ed25519 keypair and persist it as <prefix>.pub (mode
 * 0644) + <prefix>.sec (mode 0600). The 0600 on the secret matches what
 * --sign demands at load time, so freshly minted keys are immediately
 * usable without a separate chmod step.
 *
 * Refuses to overwrite an existing file (O_EXCL) — operators rotating a
 * mission key need to delete or rename the old pair first, deliberately.
 */
static int attest_keygen_run(const char *prefix, FILE *out, FILE *err)
{
    if (attest_sign_init() != ATTEST_SIGN_OK) {
        fprintf(err, "csh-attest: E205: libsodium init failed\n");
        return 3;
    }

    uint8_t pub[ATTEST_SIGN_PUBLIC_KEY_BYTES];
    uint8_t sec[ATTEST_SIGN_SECRET_KEY_BYTES];
    if (attest_sign_keypair(pub, sec) != ATTEST_SIGN_OK) {
        fprintf(err,
                "csh-attest: E205: libsodium keypair generation failed\n");
        return 3;
    }

    if (write_key_file(prefix, ".pub", 0644, pub, sizeof(pub)) != 0) {
        fprintf(err,
                "csh-attest: E204: cannot write %s.pub\n"
                "  cause: file already exists, parent dir missing, or "
                "permission denied\n"
                "  fix:   pick an unused prefix, or remove the existing "
                "%s.pub / %s.sec pair before regenerating\n",
                prefix, prefix, prefix);
        return 3;
    }
    if (write_key_file(prefix, ".sec", 0600, sec, sizeof(sec)) != 0) {
        fprintf(err,
                "csh-attest: E204: cannot write %s.sec (the .pub was "
                "written; clean up before retrying)\n",
                prefix);
        return 3;
    }
    fprintf(out, "wrote %s.pub (32B, mode 0644)\n", prefix);
    fprintf(out, "wrote %s.sec (64B, mode 0600)\n", prefix);
    return 0;
}

static int attest_cmd(struct slash *slash)
{
    bool emit = false;
    const char *sign_key_path = NULL;
    const char *verify_pubkey_path = NULL;
    const char *verify_signed_path = NULL;
    const char *remote_node = NULL;
    const char *keygen_prefix = NULL;

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
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            attest_print_help(stdout);
            return SLASH_SUCCESS;
        } else if (strcmp(arg, "--emit") == 0) {
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
        } else if (strcmp(arg, "--keygen") == 0) {
            if (i + 1 >= slash->argc) {
                fprintf(stderr,
                        "csh-attest: --keygen requires a <prefix> "
                        "(writes <prefix>.pub + <prefix>.sec)\n");
                return SLASH_EUSAGE;
            }
            keygen_prefix = slash->argv[++i];
        } else {
            fprintf(stderr, "csh-attest: unknown argument: %s\n", arg);
            return SLASH_EUSAGE;
        }
    }

    if (keygen_prefix != NULL) {
        if (emit || sign_key_path != NULL || verify_pubkey_path != NULL ||
            remote_node != NULL) {
            fprintf(stderr,
                    "csh-attest: --keygen is exclusive with "
                    "--emit/--sign/--verify/--remote\n");
            return SLASH_EUSAGE;
        }
        return attest_keygen_run(keygen_prefix, stdout, stderr);
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
         * via the `csh -i <init> "<cmd>"` positional form, so the
         * design-doc 0=valid / 1=invalid / 2=error contract reaches the
         * caller (see README "CI integration" for the script -qc wrap). */
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
                "--verify <pubkey> <signed.json>, --remote <node>, or "
                "--keygen <prefix> (run `attest --help` for details)\n");
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
        if (load_rc == ATTEST_SIGN_ERR_KEY_PERMS) {
            fprintf(stderr,
                    "csh-attest: E202: private key file world/group-readable: "
                    "%s\n"
                    "  cause: file mode is too permissive (need 0o600 or "
                    "stricter)\n"
                    "  fix:   chmod 600 %s\n",
                    sign_key_path, sign_key_path);
        } else {
            fprintf(stderr,
                    "csh-attest: E203: private key file malformed or "
                    "unreadable: %s\n"
                    "  cause: file is missing, unreadable, or not exactly %u "
                    "raw bytes (libsodium combined seed+public format)\n"
                    "  fix:   regenerate with the same tool that produced "
                    "matching keys/<name>.pub\n",
                    sign_key_path, ATTEST_SIGN_SECRET_KEY_BYTES);
        }
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
              "| --remote <node> | --keygen <prefix> | --help",
              "Emit, sign, verify, fetch, or generate keys for an attestation "
              "manifest");
#endif /* CSH_ATTEST_HAVE_SLASH */

/*
 * APM banner shown by `apm info`. csh's loader dlsym's this; missing is
 * tolerated, present overrides the default banner.
 */
void libinfo(void);
void libinfo(void)
{
    printf("csh-attest %s — read-only attestation APM\n", CSH_ATTEST_VERSION);
}

/*
 * apm_init hook. On Linux, libapm_csh's libmain calls this after walking
 * the slash/param/vmem sections. On macOS our local libmain shell (below)
 * calls it directly. Returning non-zero aborts the load (csh exit(1)).
 *
 * apm_csh declares `apm_init` as `__attribute__((weak, visibility("hidden")))`
 * in <apm/apm.h>; this strong definition overrides it.
 */
int apm_init(void);
int apm_init(void)
{
    return csh_attest_init();
}

#ifndef __linux__
/*
 * macOS dev-build APM ABI shell. On Linux these come from libapm_csh's
 * static lib via .as_link_whole(); macOS doesn't link apm_csh (libcsp
 * doesn't compile there) so we provide a minimal stand-in for the
 * compile-check build. macOS is not a load target — this never runs.
 *
 * v10 matches current csh master (see spaceinventor/libapm_csh
 * include/apm/csh_api.h:30 → APM_INIT_VERSION).
 */
const int apm_init_version = 10;

int libmain(void);
int libmain(void)
{
    return apm_init();
}
#endif /* !__linux__ */

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
