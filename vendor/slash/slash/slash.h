#pragma once

/*
 * Vendored slash compat header — exact mirror of upstream
 * spaceinventor/csh's lib/slash/include/slash/slash.h (struct shape +
 * macro registration ABI).
 *
 * csh's libapm_csh::libmain walks the `slash` ELF section after dlopen
 * and calls slash_list_add(cmd) for each entry. The struct shape, the
 * section name, and the macro alignment must match the running csh
 * BYTE-FOR-BYTE. Two failure modes seen in the wild when this is
 * wrong:
 *
 *   1. struct slash_command is too small → csh's SLIST_INSERT_HEAD
 *      writes item->next at an offset past our struct end. Since the
 *      APM emits commands packed back-to-back in its `slash` section,
 *      that write lands inside the NEXT command struct, corrupting its
 *      .name pointer. A later slash_command_find then crashes on
 *      strlen(cmd->name) when iterating.
 *
 *   2. struct slash places argv / argc at the wrong offsets → command
 *      callbacks read garbage where their argv should be. Symptom:
 *      every flag is silently dropped, every command falls into its
 *      "no flag given" / usage branch.
 *
 * Both ABIs are tracked against current spaceinventor/csh master
 * (post the int signal / int busy addition in struct slash, and post
 * the help / context additions in struct slash_command). If upstream
 * bumps the layout again, update this file AND bump APM_INIT_VERSION.
 *
 * Reference:
 *   https://github.com/spaceinventor/csh/blob/master/lib/slash/include/slash/slash.h
 *
 * Why vendor instead of wrap-fetch:
 *   - Upstream slash's completer.c uses PATH_MAX and DT_DIR without
 *     the Linux <limits.h> / dirent extensions, so it fails on Ubuntu
 *     under -Werror. We never link slash's library — only need its
 *     struct + macro for our ELF section emit.
 */

#include <stddef.h>
#include <stdbool.h>
#include <termios.h>

#ifdef __cplusplus
extern "C" {
#endif

struct slash;
typedef int (*slash_func_t)(struct slash *slash);
typedef int (*slash_func_context_t)(struct slash *slash, void *context);

/*
 * Wait function prototype. Upstream takes void* (not struct slash*) so
 * the user-implemented waitfunc can be defined without including this
 * header.
 */
typedef int (*slash_waitfunc_t)(void *slash, unsigned int ms);

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
 * struct slash_command — exact mirror of upstream. Order, types, and
 * alignment must match. csh's slash_list_add writes through .next; the
 * trailing .context field exists so csh's 56-byte stride matches ours
 * (without it the SLIST write corrupts the next command).
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
    /* Single-linked list entry (sys/queue.h SLIST_ENTRY shape). */
    struct {
        struct slash_command *sle_next;
    } next;
    void *context;
};

/*
 * struct slash — exact mirror of upstream. argv / argc MUST land at the
 * upstream offsets so command callbacks see the parsed line.
 *
 * Linux-only build assumes SLASH_HAVE_TERMIOS_H is defined upstream
 * (it always is on Linux). The `int signal` / `int busy` fields after
 * use_activate are present in current csh master.
 */
struct slash {

    /* Terminal handling */
    struct termios original;
    int fd_write;
    int fd_read;
    slash_waitfunc_t waitfunc;
    bool use_activate;
    int signal;
    int busy;

    /* Line editing */
    size_t line_size;
    const char *prompt;
    size_t prompt_length;
    size_t prompt_print_length;
    char *buffer;
    size_t cursor;
    size_t length;
    bool escaped;
    char last_char;

    /* History */
    size_t history_size;
    int history_depth;
    size_t history_avail;
    int history_rewind_length;
    char *history;
    char *history_head;
    char *history_tail;
    char *history_cursor;

    /* Command interface */
    char **argv;
    int argc;

    /* getopt state */
    char *optarg;
    int optind;
    int opterr;
    int optopt;
    int sp;

    /* Command list */
    struct slash_command *cmd_list;

    /* Re-entrant completion guard. */
    bool complete_in_completion;
};

/*
 * Resolved at dlopen time against csh's process. Declared weak so unit
 * tests (which do not link slash) can stub or omit it.
 */
__attribute__((weak)) extern int slash_list_add(struct slash_command *cmd);

/*
 * slash_command(name, func, args, help)
 *
 * Emits a `const struct slash_command` into ELF section "slash".
 * Caller writes `slash_command(foo, foo_cmd, "<args>", "<help>");` —
 * the trailing `;` is the declarator's own (the macro itself does not
 * end with `;`, which keeps -Wpedantic happy).
 */
#define slash_command(_name, _func, _args, _help)                            \
    __attribute__((section("slash"), aligned(4), used))                      \
    const struct slash_command slash_cmd_##_name = {                         \
        .name = (char *)#_name, .func = _func, .args = _args,                \
        .help = _help, .completer = NULL, .next = {NULL}, .context = NULL,   \
    }

/*
 * Variant when the user-facing command name is not a valid C identifier
 * (e.g., contains a hyphen). `_cident` is the C identifier used to name
 * the storage; `_name_str` is the literal command name csh's parser
 * will match against.
 */
#define slash_command_named(_cident, _name_str, _func, _args, _help)         \
    __attribute__((section("slash"), aligned(4), used))                      \
    const struct slash_command slash_cmd_##_cident = {                       \
        .name = (char *)(_name_str), .func = _func, .args = _args,           \
        .help = _help, .completer = NULL, .next = {NULL}, .context = NULL,   \
    }

#ifdef __cplusplus
}
#endif
