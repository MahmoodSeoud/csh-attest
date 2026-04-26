#pragma once

/*
 * Ground-side driver for `attest --remote <node>`.
 *
 * Connects to <node>:ATTEST_CSP_PORT via RDP, sends the trigger packet,
 * accumulates the bird's response stream until the connection closes,
 * writes the canonical-manifest bytes (followed by a single newline,
 * matching --emit's stdout shape) to `out`.
 *
 * Pre-condition: csp_init() + the router have been brought up by the host
 * (in production: csh; in tests: the integration harness). We never call
 * csp_init ourselves — see csp_server.h for the same contract.
 *
 * argv layout matches attest_diff_run / attest_verify_run for slash-style
 * dispatch consistency:
 *
 *   argv[0] — command label (ignored)
 *   argv[1] — destination CSP node ID (decimal, fits in uint16_t)
 *
 * Returns the design-doc shell exit code:
 *   0 — clean transfer; manifest bytes written to `out`
 *   2 — usage error (missing/garbage node ID)
 *   3 — transport error (E101: connect failed, E102: read timed out, etc.)
 */

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int attest_remote_run(int argc, char **argv, FILE *out, FILE *err);

#ifdef __cplusplus
}
#endif
