#pragma once

/*
 * attest-diff output rendering.
 *
 * Two modes:
 *   - text (default): one line per record, ✓/✗/-/+ prefix, optional ANSI
 *     colors, summary line at the end.
 *   - json (--json): machine-parseable JCS-canonical object — sorted keys,
 *     no whitespace, parseable by jcsp_parse.
 *
 * Color discipline (design doc "Output discipline"):
 *   - ANSI colors only when output is a TTY.
 *   - --json never emits ANSI.
 *   - --no-color overrides TTY detection.
 *   diff_should_color() resolves all three inputs to a single bool.
 */

#include <stdbool.h>
#include <stdio.h>

#include "diff.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool json_mode;
    bool color;
} diff_render_opts_t;

/*
 * Resolve the color flag.  Returns false when:
 *   - json_mode is true, OR
 *   - no_color flag is set, OR
 *   - the output stream is not a TTY (or fileno() fails on it).
 */
bool diff_should_color(bool json_mode, bool no_color_flag, FILE *out);

/*
 * Render the diff to `out`. Returns 0 on success, -1 on emitter or write
 * failure. Caller controls exit code based on diff_has_drift().
 */
int diff_render(FILE *out, const struct diff_result *r,
                const diff_render_opts_t *opts);

#ifdef __cplusplus
}
#endif
