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

#ifdef CSH_ATTEST_HAVE_SLASH
#include <slash/slash.h>
#include <slash/optparse.h>

static int hello_cmd(struct slash *slash)
{
    (void)slash;
    printf("hello\n");
    return SLASH_SUCCESS;
}
slash_command(hello, hello_cmd, "", "csh-attest scaffold liveness check");

/*
 * `attest --emit` writes a manifest for the running host to stdout. Session 3
 * implementation uses the non-canonical FILE* emitter; session 4 swaps in a
 * JCS-canonical emitter behind the same attest_emit() entry.
 *
 * Other modes (--remote, --sign, --json) defer to later sessions when libdtp
 * and libsodium are wired.
 */
static int attest_cmd(struct slash *slash)
{
    bool emit = false;

    optparse_t *parser = optparse_new("attest", "--emit");
    optparse_add_help(parser);
    optparse_add_set(parser, 'e', "emit", 1, (int *)&emit,
                     "Emit a local manifest to stdout");

    int argi = optparse_parse(parser, slash->argc - 1,
                              (const char **)slash->argv + 1);
    if (argi < 0) {
        optparse_del(parser);
        return SLASH_EINVAL;
    }

    if (!emit) {
        fprintf(stderr,
                "csh-attest: --emit is currently the only supported mode\n");
        optparse_del(parser);
        return SLASH_EUSAGE;
    }

    /*
     * Production output is JCS-canonical bytes. We buffer in memory so the
     * same bytes can be handed to a signing routine in a later session
     * without re-emitting. Buffer is freed before return.
     */
    struct jcs_buffer buf;
    jcs_buffer_init(&buf);

    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_canonical_init(&em, &ctx, &buf);

    int rc = attest_emit(&em);
    if (rc == 0) {
        fwrite(buf.data, 1, buf.len, stdout);
        fputc('\n', stdout);
    }

    jcs_buffer_free(&buf);
    optparse_del(parser);

    if (rc != 0) {
        fprintf(stderr, "csh-attest: emit failed (rc=%d)\n", rc);
        return SLASH_EIO;
    }
    return SLASH_SUCCESS;
}
slash_command(attest, attest_cmd, "--emit", "Emit attestation manifest");
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
