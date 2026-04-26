#pragma once

/*
 * Minimal slash compat header.
 *
 * csh's libapm_csh::libmain walks the `slash` ELF section after dlopen and
 * calls slash_list_add(cmd) for each entry. The struct shape, the section
 * name, and the macro alignment must match upstream spaceinventor/slash so
 * the host process recognises our entries.
 *
 * Why vendor instead of wrap-fetch:
 *   - Upstream slash's completer.c uses PATH_MAX and DT_DIR without the
 *     Linux-mandatory <limits.h> / Linux dirent extensions, so it fails on
 *     Ubuntu under -Werror. We never link slash's library — only need its
 *     struct + macro for our ELF section emit. Vendoring sidesteps the
 *     upstream build break entirely.
 *   - The struct + macro ABI is stable; if csh ever bumps it, we update
 *     APM_INIT_VERSION at the same time and revisit.
 *
 * Symbols `slash_list_add` and friends are weak externs resolved by csh's
 * already-loaded slash at dlopen time.
 *
 * Reference: https://github.com/spaceinventor/slash include/slash/slash.h.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct slash;
typedef int (*slash_func_t)(struct slash *slash);
typedef int (*slash_func_context_t)(struct slash *slash, void *context);
typedef void (*slash_completer_func_t)(struct slash *slash, char *token);

/* Return values used by slash command callbacks. */
#define SLASH_EXIT     ( 1)
#define SLASH_SUCCESS  ( 0)
#define SLASH_EUSAGE   (-1)
#define SLASH_EINVAL   (-2)
#define SLASH_ENOSPC   (-3)
#define SLASH_EIO      (-4)
#define SLASH_ENOMEM   (-5)
#define SLASH_ENOENT   (-6)
#define SLASH_EBREAK   (-7)

/*
 * Layout matches spaceinventor/slash. The union for func / func_ctx is a
 * named union per upstream — we keep it that way for ABI fidelity.
 */
struct slash_command {
    char *name;
    union {
        const slash_func_t func;
        const slash_func_context_t func_ctx;
    };
    const char *args;
    const char *help;
    const slash_completer_func_t completer;
    /* SLIST entry per upstream's sys/queue.h convention. */
    struct {
        struct slash_command *sle_next;
    } next;
    void *context;
};

/*
 * The slash struct itself is opaque to APM authors. We only need its
 * argv / argc fields. Keeping the layout in sync with upstream — same
 * fields, same order — so &slash->argc resolves correctly.
 */
struct slash {
    /* Terminal handling. We do not touch these but the field offsets must
     * match so argc/argv land in the right place. */
    char _reserved_terminal[256];

    /* Command interface. argv / argc are what we read. */
    char **argv;
    int argc;

    /* Trailing fields are also opaque — we never reach them. */
    char _reserved_trailing[512];
};

/*
 * Resolved at dlopen time against csh's process. Declared weak so unit
 * tests (which do not link slash) can stub or omit it.
 */
__attribute__((weak)) extern int slash_list_add(struct slash_command *cmd);

/*
 * slash_command(name, func, args, help)
 *
 * Emits a `const struct slash_command` into ELF section "slash". Callers
 * write `slash_command(foo, foo_cmd, "", "...");` — the trailing `;` is the
 * declarator's own semicolon (the macro itself doesn't end with `;`, which
 * keeps -Wpedantic happy on GCC).
 */
#define slash_command(_name, _func, _args, _help)                            \
    __attribute__((section("slash"), aligned(4), used))                      \
    const struct slash_command slash_cmd_##_name = {                         \
        .name = #_name, .func = _func, .completer = NULL,                    \
        .args = _args, .help = _help, .next = {NULL}, .context = NULL,       \
    }

/*
 * Variant when the user-facing command name is not a valid C identifier
 * (e.g., contains a hyphen). `_cident` is the C identifier used to name
 * the storage; `_name_str` is the literal command name csh's parser will
 * match against. Functionally equivalent to slash_command() otherwise.
 */
#define slash_command_named(_cident, _name_str, _func, _args, _help)         \
    __attribute__((section("slash"), aligned(4), used))                      \
    const struct slash_command slash_cmd_##_cident = {                       \
        .name = (char *)(_name_str), .func = _func, .completer = NULL,       \
        .args = _args, .help = _help, .next = {NULL}, .context = NULL,       \
    }

#ifdef __cplusplus
}
#endif
