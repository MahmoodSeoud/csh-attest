#pragma once

/*
 * Wire constants for `attest --remote` over libcsp.
 *
 * Both bird-side (csp_server.c) and ground-side (csp_client.c) include this
 * header so the contract lives in one place. Once libparam-overridable
 * knobs land (session 10, design doc 1H), these `#define`s become param
 * defaults instead of hardcoded values.
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
 * v0.1.x dev-laptop loopback; real-radio operation will revisit RDP or
 * libdtp in session 10+.
 */

#define ATTEST_CSP_PORT          100u
#define ATTEST_CSP_MAGIC         0x41u
#define ATTEST_CSP_MAX_PAYLOAD   1900u
#define ATTEST_CSP_TIMEOUT_MS    5000u
#define ATTEST_CSP_LEN_PREFIX    4u
