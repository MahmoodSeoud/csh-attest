#include <stdarg.h>
#include <stdbool.h>
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
 * Stub for the slash_list_add symbol that csh_attest.c references weakly.
 * Records each command name so the test can assert that libmain walked the
 * `slash` section and registered every slash_command(...) entry.
 */
#define SLASH_LIST_ADD_MAX_SEEN 16
static size_t slash_list_add_count;
static const char *slash_list_add_seen[SLASH_LIST_ADD_MAX_SEEN];

int slash_list_add(struct slash_command *cmd);
int slash_list_add(struct slash_command *cmd)
{
    if (slash_list_add_count < SLASH_LIST_ADD_MAX_SEEN) {
        slash_list_add_seen[slash_list_add_count] = cmd->name;
    }
    slash_list_add_count++;
    return 0;
}

static int reset_slash_stub(void **state)
{
    (void)state;
    slash_list_add_count = 0;
    for (size_t i = 0; i < SLASH_LIST_ADD_MAX_SEEN; i++) {
        slash_list_add_seen[i] = NULL;
    }
    return 0;
}

static void test_libmain_walks_slash_section(void **state)
{
    (void)state;

    /*
     * libmain should iterate the `slash` ELF section, find every
     * slash_command(...) entry in csh_attest.c, and call slash_list_add()
     * on each. csh_attest.c currently registers two: hello and attest.
     * Linker order within a section is implementation-defined; we assert
     * count + presence-by-name, not order.
     */
    assert_int_equal(libmain(), 0);
    assert_int_equal(slash_list_add_count, 2);

    bool saw_hello = false;
    bool saw_attest = false;
    for (size_t i = 0; i < slash_list_add_count; i++) {
        const char *name = slash_list_add_seen[i];
        if (name == NULL) {
            continue;
        }
        if (strcmp(name, "hello") == 0) {
            saw_hello = true;
        } else if (strcmp(name, "attest") == 0) {
            saw_attest = true;
        }
    }
    assert_true(saw_hello);
    assert_true(saw_attest);
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
