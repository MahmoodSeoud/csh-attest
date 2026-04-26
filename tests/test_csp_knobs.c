/*
 * Unit tests for the env-var-overridable CSP protocol knobs declared in
 * src/csp_protocol.h. Pure stdlib — runs on every platform we test on.
 *
 * Coverage:
 *   - default returned when env var is unset
 *   - default returned when env var is empty string
 *   - valid override returned when env var parses cleanly + in range
 *   - default returned + warning printed for unparseable values
 *   - default returned + warning printed for out-of-range values (low/high)
 *   - default returned for trailing-garbage values ("123abc")
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>

#include <cmocka.h>

#include "csp_protocol.h"

/*
 * Tear down between tests so a stray override from one case doesn't bleed
 * into the next. setenv with overwrite=1 is enough for the positive
 * cases; unsetenv ensures the unset path is clean.
 */
static int reset_env(void **state)
{
    (void)state;
    unsetenv("ATTEST_CSP_PORT");
    unsetenv("ATTEST_CSP_TIMEOUT_MS");
    return 0;
}

/* ---- attest_csp_port -------------------------------------------------- */

static void test_port_default_when_unset(void **state)
{
    (void)state;
    assert_int_equal(attest_csp_port(), ATTEST_CSP_PORT_DEFAULT);
}

static void test_port_default_when_empty(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_PORT", "", 1);
    assert_int_equal(attest_csp_port(), ATTEST_CSP_PORT_DEFAULT);
}

static void test_port_valid_override(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_PORT", "37", 1);
    assert_int_equal(attest_csp_port(), 37u);
}

static void test_port_boundary_low(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_PORT", "1", 1);
    assert_int_equal(attest_csp_port(), 1u);
}

static void test_port_boundary_high(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_PORT", "127", 1);
    assert_int_equal(attest_csp_port(), 127u);
}

static void test_port_zero_falls_back(void **state)
{
    (void)state;
    /* Port 0 is the broadcast convention in libcsp — explicitly outside
     * our 1..127 binding range. */
    setenv("ATTEST_CSP_PORT", "0", 1);
    assert_int_equal(attest_csp_port(), ATTEST_CSP_PORT_DEFAULT);
}

static void test_port_above_range_falls_back(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_PORT", "128", 1);
    assert_int_equal(attest_csp_port(), ATTEST_CSP_PORT_DEFAULT);
}

static void test_port_garbage_falls_back(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_PORT", "not-a-number", 1);
    assert_int_equal(attest_csp_port(), ATTEST_CSP_PORT_DEFAULT);
}

static void test_port_trailing_garbage_falls_back(void **state)
{
    (void)state;
    /* strtoul would accept "100abc" and report 100; we want strict
     * trailing-NUL parsing so typos can't silently change the port. */
    setenv("ATTEST_CSP_PORT", "100abc", 1);
    assert_int_equal(attest_csp_port(), ATTEST_CSP_PORT_DEFAULT);
}

/* ---- attest_csp_timeout_ms ------------------------------------------- */

static void test_timeout_default_when_unset(void **state)
{
    (void)state;
    assert_int_equal(attest_csp_timeout_ms(),
                     ATTEST_CSP_TIMEOUT_MS_DEFAULT);
}

static void test_timeout_valid_override(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_TIMEOUT_MS", "12000", 1);
    assert_int_equal(attest_csp_timeout_ms(), 12000u);
}

static void test_timeout_below_range_falls_back(void **state)
{
    (void)state;
    /* 5 (the typo case mentioned in csp_protocol.c) is below the 100ms
     * floor and must not be honoured. */
    setenv("ATTEST_CSP_TIMEOUT_MS", "5", 1);
    assert_int_equal(attest_csp_timeout_ms(),
                     ATTEST_CSP_TIMEOUT_MS_DEFAULT);
}

static void test_timeout_above_range_falls_back(void **state)
{
    (void)state;
    setenv("ATTEST_CSP_TIMEOUT_MS", "60001", 1);
    assert_int_equal(attest_csp_timeout_ms(),
                     ATTEST_CSP_TIMEOUT_MS_DEFAULT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_port_default_when_unset, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_default_when_empty, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_valid_override, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_boundary_low, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_boundary_high, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_zero_falls_back, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_above_range_falls_back, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_garbage_falls_back, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_port_trailing_garbage_falls_back, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_timeout_default_when_unset, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_timeout_valid_override, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_timeout_below_range_falls_back, reset_env, reset_env),
        cmocka_unit_test_setup_teardown(
            test_timeout_above_range_falls_back, reset_env, reset_env),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
