#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "csh_attest.h"

#ifdef __linux__
/*
 * apm_init() / libmain() spawn the CSP server thread on Linux, which calls
 * csp_bind(). Without prior csp_init() that's a null-deref. We initialize
 * CSP once in main() before driving the suite — same contract csh enforces
 * in production (host calls csp_init before loading APMs).
 */
#include <pthread.h>
#include <csp/csp.h>

static void *router_thread(void *unused)
{
    (void)unused;
    while (1) {
        csp_route_work();
    }
    return NULL;
}

static void test_csp_bring_up(void)
{
    csp_init();
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, router_thread, NULL);
    pthread_attr_destroy(&attr);
}
#endif

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
     * on each. csh_attest.c currently registers three: hello, attest,
     * and attest-diff. Linker order within a section is implementation-
     * defined; we assert count + presence-by-name, not order.
     */
    assert_int_equal(libmain(), 0);
    assert_int_equal(slash_list_add_count, 3);

    bool saw_hello = false;
    bool saw_attest = false;
    bool saw_attest_diff = false;
    for (size_t i = 0; i < slash_list_add_count; i++) {
        const char *name = slash_list_add_seen[i];
        if (name == NULL) {
            continue;
        }
        if (strcmp(name, "hello") == 0) {
            saw_hello = true;
        } else if (strcmp(name, "attest") == 0) {
            saw_attest = true;
        } else if (strcmp(name, "attest-diff") == 0) {
            saw_attest_diff = true;
        }
    }
    assert_true(saw_hello);
    assert_true(saw_attest);
    assert_true(saw_attest_diff);
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
#ifdef __linux__
    test_csp_bring_up();
#endif

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
