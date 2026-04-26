#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "csh_attest.h"

/*
 * libmain() is the dlopen entry point csh calls. We exercise it directly
 * here. Forward-declared instead of pulled from a public header — it is
 * intentionally not part of csh_attest.h's surface (the .h is for our own
 * code, the .so ABI symbols live in the .c).
 */
int libmain(void);
int apm_init(void);

#ifdef CSH_ATTEST_HAVE_SLASH
#include <slash.h>

/*
 * Provide a stub for the slash_list_add symbol that csh_attest.c references
 * weakly. Counts invocations and records the last-added command name so the
 * test can assert that libmain walked the `slash` section and registered the
 * hello command.
 */
static int slash_list_add_count;
static const char *slash_list_add_last_name;

int slash_list_add(struct slash_command *cmd);
int slash_list_add(struct slash_command *cmd)
{
    slash_list_add_count++;
    slash_list_add_last_name = cmd->name;
    return 0;
}

static int reset_slash_stub(void **state)
{
    (void)state;
    slash_list_add_count = 0;
    slash_list_add_last_name = NULL;
    return 0;
}

static void test_libmain_walks_slash_section(void **state)
{
    (void)state;

    /*
     * libmain should iterate the `slash` ELF section, find our hello_cmd
     * entry, call slash_list_add() on it, then forward to apm_init() (which
     * returns 0). One slash entry → exactly one slash_list_add invocation.
     */
    assert_int_equal(libmain(), 0);
    assert_int_equal(slash_list_add_count, 1);
    assert_non_null(slash_list_add_last_name);
    assert_string_equal(slash_list_add_last_name, "hello");
}
#endif /* CSH_ATTEST_HAVE_SLASH */

static void test_csh_attest_init_returns_zero(void **state)
{
    (void)state;
    assert_int_equal(csh_attest_init(), 0);
}

static void test_apm_init_returns_zero(void **state)
{
    (void)state;
    assert_int_equal(apm_init(), 0);
}

#ifndef CSH_ATTEST_HAVE_SLASH
static void test_libmain_returns_zero_without_slash(void **state)
{
    (void)state;
    /* On macOS / non-Linux dev builds the section walker compiles out and
     * libmain devolves to apm_init(). */
    assert_int_equal(libmain(), 0);
}
#endif

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_csh_attest_init_returns_zero),
        cmocka_unit_test(test_apm_init_returns_zero),
#ifdef CSH_ATTEST_HAVE_SLASH
        cmocka_unit_test_setup_teardown(
            test_libmain_walks_slash_section, reset_slash_stub, NULL),
#else
        cmocka_unit_test(test_libmain_returns_zero_without_slash),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
