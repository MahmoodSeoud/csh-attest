/*
 * Bird-side CSP service handler. Accepts connections on ATTEST_CSP_PORT,
 * emits the canonical attestation manifest into the connection's RDP
 * stream, closes.
 *
 * Wire shape (one round-trip, no protocol versioning yet):
 *
 *   ground -> bird : single-byte trigger (ATTEST_CSP_MAGIC)
 *   bird   -> ground : N data packets carrying canonical manifest bytes
 *   bird   -> ground : connection close (ground sees csp_read return NULL)
 *
 * The trigger packet exists so bird can confirm the connection is live
 * before it pays the cost of walking /proc/modules + /etc + /sys. Without
 * it a flapping connection would burn introspection budget for no reason.
 *
 * Thread runs for the lifetime of the csh process. apm_init() fires it
 * and forgets it — no join, no stop hook. csh's exit unwinds via atexit.
 */

#include "csp_server.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <csp/csp.h>
#include <csp/csp_buffer.h>

#include "attest.h"
#include "csp_protocol.h"
#include "jcs.h"

/*
 * Idempotent guard. If apm_init() somehow fires twice (the host re-loads
 * the APM, or a test calls attest_csp_server_start manually after a load),
 * the second call returns success without spawning a duplicate listener.
 */
static atomic_int server_started;

/*
 * Send a 4-byte big-endian length header followed by the manifest body in
 * ATTEST_CSP_MAX_PAYLOAD-sized chunks. Length prefix lets the ground side
 * stop reading after `len` bytes without depending on connection-close
 * detection (which is unreliable without RDP).
 *
 * Returns 0 on success, -1 if any csp_buffer_get fails (operator should
 * bump csp:buffer_count). csp_send transfers ownership of the packet, so
 * the caller never frees on the success path; the failure path frees the
 * unsent packet here.
 */
static int send_manifest_chunked(csp_conn_t *conn,
                                 const uint8_t *bytes, size_t len)
{
    csp_packet_t *header = csp_buffer_get(0);
    if (header == NULL) {
        return -1;
    }
    /* Big-endian uint32. Manifest size cap is 200 KB per design doc 1F so
     * 32-bit length is comfortable headroom. */
    uint32_t be = (uint32_t)len;
    header->data[0] = (uint8_t)(be >> 24);
    header->data[1] = (uint8_t)(be >> 16);
    header->data[2] = (uint8_t)(be >> 8);
    header->data[3] = (uint8_t)(be);
    header->length = ATTEST_CSP_LEN_PREFIX;
    csp_send(conn, header);

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > ATTEST_CSP_MAX_PAYLOAD) {
            chunk = ATTEST_CSP_MAX_PAYLOAD;
        }
        csp_packet_t *pkt = csp_buffer_get(0);
        if (pkt == NULL) {
            return -1;
        }
        memcpy(pkt->data, bytes + off, chunk);
        pkt->length = (uint16_t)chunk;
        csp_send(conn, pkt);
        off += chunk;
    }
    return 0;
}

/*
 * Drain the trigger packet (its content is unused — the connection itself
 * is the activation signal), walk the introspection field table into a
 * fresh canonical buffer, send the result back as a length-prefixed
 * chunked stream, free the buffer.
 */
static void handle_one_request(csp_conn_t *conn)
{
    csp_packet_t *trigger = csp_read(conn, attest_csp_timeout_ms());
    if (trigger != NULL) {
        csp_buffer_free(trigger);
    }

    struct jcs_buffer buf;
    jcs_buffer_init(&buf);
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_canonical_init(&em, &ctx, &buf);

    int rc = attest_emit(&em);
    if (rc != 0) {
        fprintf(stderr,
                "csh-attest: emit failed in CSP server (rc=%d)\n", rc);
        jcs_buffer_free(&buf);
        return;
    }

    if (send_manifest_chunked(conn, buf.data, buf.len) != 0) {
        fprintf(stderr,
                "csh-attest: out of CSP buffers in server\n");
    }

    jcs_buffer_free(&buf);
}

static void *server_thread(void *unused)
{
    (void)unused;

    csp_socket_t sock = {0};
    unsigned port = attest_csp_port();
    if (csp_bind(&sock, port) != 0) {
        fprintf(stderr,
                "csh-attest: csp_bind(%u) failed; server thread exiting\n",
                port);
        return NULL;
    }
    /* Backlog of 4 — operator-driven request rate, not high-rate
     * automation. A larger backlog only helps if accepts queue up faster
     * than the introspection walk completes (~10 ms typical). */
    if (csp_listen(&sock, 4) != 0) {
        fprintf(stderr,
                "csh-attest: csp_listen failed; server thread exiting\n");
        return NULL;
    }

    while (1) {
        /*
         * CSP_MAX_TIMEOUT blocks indefinitely. The thread runs forever
         * in production and is leaked on test exit; that's acceptable
         * since APMs do not unload (see csp_server.h).
         */
        csp_conn_t *conn = csp_accept(&sock, CSP_MAX_TIMEOUT);
        if (conn == NULL) {
            continue;
        }
        handle_one_request(conn);
        csp_close(conn);
    }
    return NULL;
}

int attest_csp_server_start(void)
{
    int already = atomic_exchange(&server_started, 1);
    if (already) {
        return 0;
    }

    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        return -1;
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_t tid;
    int rc = pthread_create(&tid, &attr, server_thread, NULL);
    pthread_attr_destroy(&attr);
    return rc == 0 ? 0 : -1;
}
