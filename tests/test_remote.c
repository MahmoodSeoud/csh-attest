/*
 * Loopback integration test for `attest --remote`.
 *
 * Exercises the full bird → ground round trip in a single process:
 *
 *   csp_init + router thread     (host-side init, csh would do this in prod)
 *   csh_attest_init              (spawns the bird-side listener thread)
 *   attest_remote_run            (ground-side fetch over CSP loopback)
 *
 * Assertions:
 *   - returned bytes are non-empty
 *   - returned bytes are JCS-canonical and parse cleanly
 *   - the parsed manifest is a top-level object containing schema_version
 *
 * Linux-only — libcsp's POSIX driver doesn't compile on macOS.
 */

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <csp/csp.h>
#include <csp/interfaces/csp_if_lo.h>

#include "csh_attest.h"
#include "csp_client.h"
#include "csp_protocol.h"
#include "jcs_parse.h"

/*
 * Test bird's CSP node id. Arbitrary — picked away from 0 (CSP "broadcast"
 * connotation) and 255 (the example default) to keep this test self-
 * contained. The client connects to this address; loopback routes back
 * to the listener bound to port 100 in this same process.
 */
#define TEST_NODE_ID 5u

/* ------------------------------------------------------------------ */
/* One-time CSP setup.                                                */
/* ------------------------------------------------------------------ */

static void *router_thread(void *unused)
{
    (void)unused;
    fprintf(stderr, "test_remote: router thread started\n");
    /* Print first few packets routed so CI logs reveal whether the
     * router is processing the trigger and the response. */
    int routed = 0;
    while (1) {
        int rc = csp_route_work();
        if (rc == CSP_ERR_NONE && routed < 8) {
            fprintf(stderr, "test_remote: router processed packet %d\n",
                    ++routed);
        }
    }
    return NULL;
}

static int suite_setup(void **state)
{
    (void)state;

    csp_init();
    /* Set the loopback address AFTER csp_init — csp_init only sets the
     * netmask. Without a non-zero addr the client's connect would race
     * with the loopback shortcut path that compares idout->dst to
     * csp_if_lo.addr. Setting it explicitly removes the ambiguity. */
    csp_if_lo.addr = TEST_NODE_ID;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t tid;
    int rc = pthread_create(&tid, &attr, router_thread, NULL);
    pthread_attr_destroy(&attr);
    assert_int_equal(rc, 0);

    /* csh_attest_init spawns the bird-side CSP listener bound to
     * ATTEST_CSP_PORT. After this returns the listener is alive in a
     * detached thread — no cleanup needed; the process exits when the
     * test binary exits. */
    assert_int_equal(csh_attest_init(), 0);

    /*
     * Tiny grace period for the listener thread to reach csp_accept
     * before the first client connect. Without this the very first
     * csp_connect can race the bind. RDP would retry, but we'd rather
     * keep the per-test latency predictable.
     */
    usleep(50 * 1000);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

static int run_remote(const char *node, char **out_buf, char **err_buf)
{
    size_t out_len = 0, err_len = 0;
    FILE *out = open_memstream(out_buf, &out_len);
    FILE *err = open_memstream(err_buf, &err_len);
    char *argv[] = {(char *)"attest --remote", (char *)node};
    int rc = attest_remote_run(2, argv, out, err);
    fclose(out);
    fclose(err);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Tests.                                                             */
/* ------------------------------------------------------------------ */

static void test_remote_happy_path(void **state)
{
    (void)state;
    char node[16];
    snprintf(node, sizeof(node), "%u", TEST_NODE_ID);

    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_remote(node, &out_buf, &err_buf);
    if (rc != 0) {
        /* Diagnostic — surfaces the actual stderr text + any partial
         * stdout in the CI log when the loopback round-trip fails. */
        print_error("attest_remote_run rc=%d\n", rc);
        print_error("stderr: %s\n", err_buf ? err_buf : "(null)");
        print_error("stdout: %s\n", out_buf ? out_buf : "(null)");
    }
    assert_int_equal(rc, 0);
    assert_int_equal(strlen(err_buf), 0);

    /*
     * `attest_remote_run` writes the canonical bytes followed by a single
     * trailing newline (matching --emit's stdout convention). Strip the
     * newline before handing the bytes to the JCS-canonical parser.
     */
    size_t out_len = strlen(out_buf);
    assert_true(out_len > 0);
    assert_int_equal(out_buf[out_len - 1], '\n');

    struct jcsp_value v;
    int parse_rc = jcsp_parse((const uint8_t *)out_buf, out_len - 1, &v);
    assert_int_equal(parse_rc, 0);
    assert_int_equal(v.type, JCSP_OBJECT);

    /* Spot-check: schema_version must be present (one of the four required
     * v0.1.x fields). Sorted-key access is positional only AFTER iteration
     * confirms the key, so loop. */
    bool saw_schema_version = false;
    for (size_t i = 0; i < v.u.object.n; i++) {
        if (strcmp(v.u.object.members[i].key, "schema_version") == 0) {
            saw_schema_version = true;
            assert_int_equal(v.u.object.members[i].value.type, JCSP_STRING);
            assert_string_equal(v.u.object.members[i].value.u.string.bytes,
                                "0.1.0");
            break;
        }
    }
    assert_true(saw_schema_version);

    jcsp_value_free(&v);
    free(out_buf);
    free(err_buf);
}

static void test_remote_rejects_bad_node_id(void **state)
{
    (void)state;
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_remote("not-a-number", &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    assert_non_null(strstr(err_buf, "E001"));
    free(out_buf);
    free(err_buf);
}

static void test_remote_rejects_overflow_node_id(void **state)
{
    (void)state;
    /* 65536 = 0x10000, one past the 16-bit CSP node-id ceiling. */
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_remote("65536", &out_buf, &err_buf);
    assert_int_equal(rc, 2);
    free(out_buf);
    free(err_buf);
}

static void test_remote_unreachable_node_returns_three(void **state)
{
    (void)state;
    /*
     * Address 200 is not the loopback addr and no interface is configured
     * to handle it. csp_connect either fails to set up the connection or
     * the read times out — both surface as exit 3 with an E1xx code.
     */
    char *out_buf = NULL, *err_buf = NULL;
    int rc = run_remote("200", &out_buf, &err_buf);
    assert_int_equal(rc, 3);
    assert_non_null(strstr(err_buf, "E10"));
    free(out_buf);
    free(err_buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_remote_happy_path),
        cmocka_unit_test(test_remote_rejects_bad_node_id),
        cmocka_unit_test(test_remote_rejects_overflow_node_id),
        cmocka_unit_test(test_remote_unreachable_node_returns_three),
    };
    return cmocka_run_group_tests(tests, suite_setup, NULL);
}
