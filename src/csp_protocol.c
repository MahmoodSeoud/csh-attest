/*
 * Runtime knob accessors for the CSP protocol constants.
 *
 * Operators set ATTEST_CSP_PORT and ATTEST_CSP_TIMEOUT_MS in the bird's
 * environment (typically systemd unit, csh launch wrapper, or interactive
 * shell) to retune without recompiling. Both bird-side csp_server.c and
 * ground-side csp_client.c call these accessors instead of the
 * compile-time *_DEFAULT macros.
 *
 * Lookup happens on every call — no caching — so tests can rotate values
 * mid-suite via setenv()/unsetenv() without restarting the process. The
 * call sites are cold (server bind once at startup, one client connect
 * per --remote invocation, two reads per round trip), so getenv overhead
 * is irrelevant.
 *
 * Validation: out-of-range or unparseable values fall back to the
 * compile-time default with a one-line stderr warning so misconfig is
 * visible to the operator without crashing the bird.
 *
 * Platform: pure stdlib (no libcsp). Compiles and runs on macOS dev
 * builds and the Linux production targets identically — keeps the
 * env-parse logic exercised by `tests/test_csp_knobs.c` everywhere.
 */

#include "csp_protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned env_uint_clamp(const char *name, unsigned dfl,
                               unsigned lo, unsigned hi)
{
    const char *raw = getenv(name);
    if (raw == NULL || raw[0] == '\0') {
        return dfl;
    }
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0' ||
        v < (unsigned long)lo || v > (unsigned long)hi) {
        fprintf(stderr,
                "csh-attest: %s=\"%s\" out of range [%u..%u]; using %u\n",
                name, raw, lo, hi, dfl);
        return dfl;
    }
    return (unsigned)v;
}

unsigned attest_csp_port(void)
{
    /* csh's bundled libcsp is compiled with CSP_PORT_MAX_BIND=16 (see
     * spaceinventor/csh lib/csp/meson_options.txt). Anything above 16
     * silently fails csp_bind on the bird side. Port 0 is the CSP
     * broadcast convention, so the usable window is 1..16. */
    return env_uint_clamp("ATTEST_CSP_PORT",
                          ATTEST_CSP_PORT_DEFAULT, 1u, 16u);
}

unsigned attest_csp_timeout_ms(void)
{
    /* 100ms floor catches the typo case (ATTEST_CSP_TIMEOUT_MS=5 instead
     * of 5000) without locking out genuinely fast loopback test setups.
     * 60s ceiling is generous for a single packet read on a real radio
     * pass; longer than that and the operator should be reconsidering
     * the protocol, not the timeout. */
    return env_uint_clamp("ATTEST_CSP_TIMEOUT_MS",
                          ATTEST_CSP_TIMEOUT_MS_DEFAULT, 100u, 60000u);
}
