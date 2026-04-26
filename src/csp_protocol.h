#pragma once

/*
 * Wire constants for `attest --remote` over libcsp.
 *
 * Both bird-side (csp_server.c) and ground-side (csp_client.c) include this
 * header so the contract lives in one place. Once libparam-overridable
 * knobs land (session 10, design doc 1H), these `#define`s become param
 * defaults instead of hardcoded values.
 *
 *   ATTEST_CSP_PORT       — CSP destination port for attest connections.
 *                           Default 100 per design doc 1H. Bird binds here;
 *                           ground connects here.
 *   ATTEST_CSP_MAGIC      — single-byte trigger sent by ground after
 *                           connect. Bird discards content but reads the
 *                           packet to confirm the connection is live before
 *                           starting to emit. The byte itself ('A' = 0x41,
 *                           "attest") is informational only.
 *   ATTEST_CSP_MAX_PAYLOAD — bytes of manifest data per CSP packet. Sized
 *                           well below buffer_size=2048 (set in meson.build)
 *                           to leave headroom for CSP's internal headers.
 *   ATTEST_CSP_TIMEOUT_MS — accept / read timeouts. 5 seconds gives the
 *                           ground side enough wall-clock for slow links
 *                           while still surfacing dead connections.
 */

#define ATTEST_CSP_PORT          100u
#define ATTEST_CSP_MAGIC         0x41u
#define ATTEST_CSP_MAX_PAYLOAD   1900u
#define ATTEST_CSP_TIMEOUT_MS    5000u
