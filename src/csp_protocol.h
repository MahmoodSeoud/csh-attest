#pragma once

/*
 * Wire constants and runtime knobs for `attest --remote` over libcsp.
 *
 * Compile-time defaults:
 *   ATTEST_CSP_PORT_DEFAULT       100      (env: ATTEST_CSP_PORT,
 *                                            range 1..127)
 *   ATTEST_CSP_TIMEOUT_MS_DEFAULT 5000     (env: ATTEST_CSP_TIMEOUT_MS,
 *                                            range 100..60000)
 *   ATTEST_CSP_MAGIC              0x41     (protocol-fixed; not overridable)
 *   ATTEST_CSP_MAX_PAYLOAD        1900     (linked to libcsp buffer_size;
 *                                            not overridable)
 *   ATTEST_CSP_LEN_PREFIX         4        (wire-format constant)
 *
 * Always call the accessor functions at runtime — they read the env
 * override on each invocation and fall back to the *_DEFAULT macro on
 * missing or invalid values. The bird and the ground side must agree
 * on port; mismatched env vars across the two processes will silently
 * fail to connect.
 *
 * Protocol (no RDP — plain CSP, length-prefixed for robust EOS):
 *
 *   ground -> bird:  1 byte trigger (ATTEST_CSP_MAGIC)
 *   bird   -> ground: 4 bytes big-endian manifest_length, then
 *                     manifest_length bytes of canonical-manifest data
 *                     split across N packets of <= ATTEST_CSP_MAX_PAYLOAD
 *   bird csp_close.
 *
 * Without RDP we cannot rely on connection-close to signal end-of-stream;
 * the length prefix lets the ground side stop reading once it has received
 * the full payload. Trade-off: no automatic retransmit. Acceptable for
 * the dev-laptop loopback path; real-radio operation will revisit RDP or
 * libdtp in a later session.
 */

#define ATTEST_CSP_PORT_DEFAULT          100u
#define ATTEST_CSP_MAGIC                 0x41u
#define ATTEST_CSP_MAX_PAYLOAD           1900u
#define ATTEST_CSP_TIMEOUT_MS_DEFAULT    5000u
#define ATTEST_CSP_LEN_PREFIX            4u

#ifdef __cplusplus
extern "C" {
#endif

unsigned attest_csp_port(void);
unsigned attest_csp_timeout_ms(void);

#ifdef __cplusplus
}
#endif
