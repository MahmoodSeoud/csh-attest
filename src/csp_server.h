#pragma once

/*
 * Bird-side CSP service handler for `attest --remote`.
 *
 * After csh has called csp_init() + brought up the router, our APM's
 * apm_init() invokes attest_csp_server_start(). That spawns a detached
 * pthread that binds ATTEST_CSP_PORT and answers every incoming connection
 * by emitting the canonical attestation manifest into the connection's
 * RDP stream and closing.
 *
 * The thread runs for the lifetime of the csh process. There is no stop
 * function — APMs do not unload at runtime; csh exit() unwinds atexit().
 *
 * Thread safety: csh-attest's introspection is read-only and re-entrant
 * (each call walks /proc, /sys, runs uname() into a stack-local). One
 * accept loop is therefore enough; no per-connection workers needed for
 * the v0.x request rate (manual operator pings, not high-rate automation).
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Spawn the CSP listener thread. Returns 0 on success, non-zero on
 * pthread_create failure. Caller is csh-attest's apm_init() in production
 * and the integration test harness in unit tests.
 *
 * Idempotent: a second call returns 0 without spawning another thread.
 * (Real APMs only call once at load time, but the integration test
 * harness benefits from the guarantee.)
 *
 * Pre-condition: csp_init() must have been called by the host. We don't
 * call it ourselves — that is csh's responsibility, and double-init is a
 * subtle category of bug we'd rather avoid by contract.
 */
int attest_csp_server_start(void);

#ifdef __cplusplus
}
#endif
