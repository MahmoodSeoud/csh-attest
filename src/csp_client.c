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

    csp_conn_t *conn = csp_connect(CSP_PRIO_NORM, node, ATTEST_CSP_PORT,
                                   ATTEST_CSP_TIMEOUT_MS, CSP_O_RDP);
    if (conn == NULL) {
        fprintf(err,
                "csh-attest: E101: connect to node %u port %u failed\n",
                node, ATTEST_CSP_PORT);
        return 3;
    }

    /* Send the trigger byte. csp_send transfers packet ownership. */
    csp_packet_t *trigger = csp_buffer_get(0);
    if (trigger == NULL) {
        fprintf(err, "csh-attest: E103: out of CSP buffers\n");
        csp_close(conn);
        return 3;
    }
    trigger->data[0] = (uint8_t)ATTEST_CSP_MAGIC;
    trigger->length = 1;
    csp_send(conn, trigger);

    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    int rc = 0;
    while (1) {
        csp_packet_t *p = csp_read(conn, ATTEST_CSP_TIMEOUT_MS);
        if (p == NULL) {
            /* Either clean close or timeout. RDP signals a normal close
             * by returning NULL; on a real link a stuck peer also looks
             * the same to us. We treat any NULL as end-of-stream and let
             * the post-loop sanity check (len > 0) decide. */
            break;
        }
        if (buf_append(&buf, &len, &cap, p->data, p->length) != 0) {
            csp_buffer_free(p);
            fprintf(err, "csh-attest: E901: out of memory accumulating manifest\n");
            rc = 3;
            free(buf);
            csp_close(conn);
            return rc;
        }
        csp_buffer_free(p);
    }
    csp_close(conn);

    if (len == 0) {
        fprintf(err,
                "csh-attest: E102: empty response from node %u\n", node);
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
