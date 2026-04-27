/*
 * Ground-side `attest --remote <node>` driver.
 *
 * Connects via RDP, sends a trigger packet, drains the response stream
 * into a heap buffer, writes the manifest bytes to the caller's FILE*.
 *
 * The caller (slash dispatch in csh_attest.c, or the integration test)
 * is responsible for csp_init / router setup. This driver is pure
 * client-side: open, send, drain, close.
 */

#include "csp_client.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <csp/csp.h>
#include <csp/csp_buffer.h>

#include "csp_protocol.h"

/*
 * Parse argv[1] as a CSP node ID (decimal, 0..65535). Returns -1 if the
 * input is missing, empty, contains non-digit characters, or overflows.
 */
static int parse_node(const char *s, uint16_t *out)
{
    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    uint32_t v = 0;
    for (size_t i = 0; s[i] != '\0'; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        v = v * 10u + (uint32_t)(s[i] - '0');
        if (v > 0xFFFFu) {
            return -1;
        }
    }
    *out = (uint16_t)v;
    return 0;
}

/*
 * Append `len` bytes onto a growable heap buffer. Doubles capacity on
 * overflow. Returns 0 on success, -1 on allocation failure.
 */
static int buf_append(uint8_t **buf, size_t *len, size_t *cap,
                      const uint8_t *bytes, size_t n)
{
    if (*len + n > *cap) {
        size_t new_cap = (*cap == 0) ? 4096 : *cap;
        while (new_cap < *len + n) {
            new_cap *= 2;
        }
        uint8_t *resized = realloc(*buf, new_cap);
        if (resized == NULL) {
            return -1;
        }
        *buf = resized;
        *cap = new_cap;
    }
    memcpy(*buf + *len, bytes, n);
    *len += n;
    return 0;
}

int attest_remote_run(int argc, char **argv, FILE *out, FILE *err)
{
    if (argc != 2) {
        fprintf(err,
                "csh-attest: usage: attest --remote <node>\n");
        return 2;
    }
    uint16_t node;
    if (parse_node(argv[1], &node) != 0) {
        fprintf(err,
                "csh-attest: E001: invalid CSP node id: %s\n", argv[1]);
        return 2;
    }

    unsigned port = attest_csp_port();
    unsigned timeout_ms = attest_csp_timeout_ms();
    csp_conn_t *conn = csp_connect(CSP_PRIO_NORM, node, port,
                                   timeout_ms, CSP_O_NONE);
    if (conn == NULL) {
        fprintf(err,
                "csh-attest: E101: connect to node %u port %u failed\n"
                "  cause: bird unreachable, port mismatch, or libcsp routing "
                "not configured for this node\n"
                "  fix:   verify ATTEST_CSP_PORT matches on bird and ground "
                "(both default 100); confirm with `csp_ping %u`; check the "
                "router has a route to node %u\n",
                node, port, node, node);
        return 3;
    }

    /* Send the trigger byte. csp_send transfers packet ownership. */
    csp_packet_t *trigger = csp_buffer_get(0);
    if (trigger == NULL) {
        fprintf(err,
                "csh-attest: E103: out of CSP buffers (no packet for trigger)\n"
                "  cause: libcsp's packet pool is exhausted — another caller "
                "is holding all buffers, or buffer_count is sized too small\n"
                "  fix:   raise csp:buffer_count in meson_options.txt (default "
                "8); on the bird, check `csp ps` for stuck connections\n");
        csp_close(conn);
        return 3;
    }
    trigger->data[0] = (uint8_t)ATTEST_CSP_MAGIC;
    trigger->length = 1;
    csp_send(conn, trigger);

    /*
     * Read the 4-byte big-endian length prefix from the bird's first
     * response packet. Per the protocol the prefix is a self-contained
     * packet of exactly ATTEST_CSP_LEN_PREFIX bytes — it does not share
     * a packet with manifest data.
     */
    csp_packet_t *header = csp_read(conn, timeout_ms);
    if (header == NULL) {
        fprintf(err,
                "csh-attest: E102: timed out waiting for length header from "
                "node %u (after %u ms)\n"
                "  cause: bird's csh-attest APM is not running, the bird "
                "process is wedged, or the link dropped mid-handshake\n"
                "  fix:   raise ATTEST_CSP_TIMEOUT_MS (default 5000) for slow "
                "links; on the bird, confirm the APM is loaded with `apm info` "
                "and that ATTEST_CSP_PORT matches the ground side\n",
                node, timeout_ms);
        csp_close(conn);
        return 3;
    }
    if (header->length != ATTEST_CSP_LEN_PREFIX) {
        fprintf(err,
                "csh-attest: E104: malformed length header (got %u bytes, "
                "expected %u)\n"
                "  cause: bird is speaking a different wire protocol — likely "
                "a csh-attest version mismatch, or libcsp framing corruption "
                "on a noisy link\n"
                "  fix:   confirm the bird and ground are running matching "
                "csh-attest versions (`apm info` on the bird, `cat VERSION` "
                "on the ground); rerun if the link is intermittent\n",
                header->length, ATTEST_CSP_LEN_PREFIX);
        csp_buffer_free(header);
        csp_close(conn);
        return 3;
    }
    size_t expected = ((size_t)header->data[0] << 24) |
                      ((size_t)header->data[1] << 16) |
                      ((size_t)header->data[2] << 8) |
                      ((size_t)header->data[3]);
    csp_buffer_free(header);

    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    int rc = 0;
    while (len < expected) {
        csp_packet_t *p = csp_read(conn, timeout_ms);
        if (p == NULL) {
            fprintf(err,
                    "csh-attest: E102: short read from node %u "
                    "(got %zu of %zu bytes, %u ms per-packet timeout)\n"
                    "  cause: bird stopped sending mid-stream — process "
                    "crashed, link dropped, or libcsp buffer exhaustion on "
                    "the bird side\n"
                    "  fix:   rerun (the protocol is single-shot, no resume "
                    "yet); raise ATTEST_CSP_TIMEOUT_MS for slow links; check "
                    "the bird's stderr / dmesg for an APM crash\n",
                    node, len, expected, timeout_ms);
            free(buf);
            csp_close(conn);
            return 3;
        }
        if (buf_append(&buf, &len, &cap, p->data, p->length) != 0) {
            csp_buffer_free(p);
            fprintf(err, "csh-attest: E901: out of memory accumulating manifest\n");
            free(buf);
            csp_close(conn);
            return 3;
        }
        csp_buffer_free(p);
    }
    csp_close(conn);

    if (len == 0) {
        fprintf(err,
                "csh-attest: E102: empty response from node %u "
                "(bird advertised 0-byte payload)\n"
                "  cause: bird-side emit/sign failed before any manifest "
                "bytes were produced — likely a missing key file or a "
                "broken introspection adapter on the bird\n"
                "  fix:   on the bird, run `attest --emit` locally to "
                "reproduce; check the bird's stderr for the underlying "
                "Exxx code; verify the signing key path is configured\n",
                node);
        free(buf);
        return 3;
    }

    if (fwrite(buf, 1, len, out) != len) {
        fprintf(err, "csh-attest: E901: short write to output stream\n");
        rc = 3;
    } else {
        fputc('\n', out);
    }

    free(buf);
    return rc;
}
