/*
 * Verifies attest_print_help() renders the four documented subcommands,
 * the env-var knob names, and the design-doc exit-code legend. The help
 * helper lives outside CSH_ATTEST_HAVE_SLASH so this runs on macOS too —
 * it's the only cross-platform proof that `attest --help` text stays
 * coherent with the README "Error codes" + "Runtime knobs" sections.
 */

#include <setjmp.h>  /* cmocka.h needs this transitively */
#include <stdarg.h>  /* and this */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "csh_attest.h"

/* Render attest_print_help into a fixed buffer via a tmpfile() round-trip
 * (open_memstream isn't on macOS by default; tmpfile is in C99). */
static size_t render_help(char *out, size_t cap)
{
    FILE *fp = tmpfile();
    assert_non_null(fp);
    attest_print_help(fp);
    rewind(fp);
    size_t n = fread(out, 1, cap - 1, fp);
    out[n] = '\0';
    fclose(fp);
    return n;
}

static void test_help_lists_all_four_subcommands(void **state)
{
    (void)state;
    char buf[4096];
    size_t n = render_help(buf, sizeof(buf));
    assert_true(n > 0);
    /* Each subcommand verb appears in the rendered help. */
    assert_non_null(strstr(buf, "--emit"));
    assert_non_null(strstr(buf, "--sign"));
    assert_non_null(strstr(buf, "--verify"));
    assert_non_null(strstr(buf, "--remote"));
    assert_non_null(strstr(buf, "attest-diff"));
}

static void test_help_documents_env_vars(void **state)
{
    (void)state;
    char buf[4096];
    render_help(buf, sizeof(buf));
    /* Both runtime knobs (README "Runtime knobs") show up by name. */
    assert_non_null(strstr(buf, "ATTEST_CSP_PORT"));
    assert_non_null(strstr(buf, "ATTEST_CSP_TIMEOUT_MS"));
    /* Defaults match the README table — drift here means the help and
     * the README disagree about what the knobs do. */
    assert_non_null(strstr(buf, "default 13"));
    assert_non_null(strstr(buf, "default 5000"));
}

static void test_help_documents_exit_code_contract(void **state)
{
    (void)state;
    char buf[4096];
    render_help(buf, sizeof(buf));
    /* The 0/1/2/3 exit-code contract is the design-doc surface every
     * CI gate dispatches on. If this drifts the README "case $?" example
     * is also wrong. */
    assert_non_null(strstr(buf, "exit codes:"));
    assert_non_null(strstr(buf, "0"));
    assert_non_null(strstr(buf, "1"));
    assert_non_null(strstr(buf, "2"));
    assert_non_null(strstr(buf, "3"));
    assert_non_null(strstr(buf, "E101..E105"));
}

static void test_help_includes_project_version(void **state)
{
    (void)state;
    char buf[4096];
    render_help(buf, sizeof(buf));
    /* CSH_ATTEST_VERSION is injected by meson from project_version().
     * If the macro isn't wired the help renders as "csh-attest <empty>"
     * — catch that here so a future meson refactor that drops the -D
     * flag fails loudly instead of silently. */
    assert_non_null(strstr(buf, CSH_ATTEST_VERSION));
    assert_true(strlen(CSH_ATTEST_VERSION) >= 5);  /* e.g. "0.3.2" */
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_help_lists_all_four_subcommands),
        cmocka_unit_test(test_help_documents_env_vars),
        cmocka_unit_test(test_help_documents_exit_code_contract),
        cmocka_unit_test(test_help_includes_project_version),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
