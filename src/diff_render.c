/*
 * attest-diff output rendering — text (ANSI-optional) and JSON (canonical).
 */

#include "diff_render.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jcs.h"
#include "jcs_parse.h"

/* ------------------------------------------------------------------ */
/* Color resolution.                                                  */
/* ------------------------------------------------------------------ */

bool diff_should_color(bool json_mode, bool no_color_flag, FILE *out)
{
    if (json_mode || no_color_flag) {
        return false;
    }
    int fd = fileno(out);
    return fd >= 0 && isatty(fd) != 0;
}

/* ------------------------------------------------------------------ */
/* Text mode.                                                         */
/* ------------------------------------------------------------------ */

/*
 * Re-emit a value through the canonical emitter into a malloc'd, NUL-
 * terminated string. Caller owns the result and must free() it.
 */
static int value_to_canonical_string(const struct jcsp_value *v, char **out_str)
{
    struct jcs_buffer buf;
    jcs_buffer_init(&buf);
    if (jcsp_emit(v, &buf) != 0) {
        jcs_buffer_free(&buf);
        return -1;
    }
    if (jcs_buffer_append_nul(&buf) != 0) {
        jcs_buffer_free(&buf);
        return -1;
    }
    /* Transfer ownership: skip jcs_buffer_free, hand caller buf.data. */
    *out_str = (char *)buf.data;
    return 0;
}

/*
 * Status prefix glyph. UTF-8 ✓/✗ (3 bytes each) plus ASCII +/- for
 * one-side-only entries. Bytewise — terminals + common log scrapers handle
 * UTF-8; --json mode bypasses this entirely.
 */
static const char *status_glyph(diff_status_t s)
{
    switch (s) {
    case DIFF_MATCH:    return "\xE2\x9C\x93"; /* ✓ */
    case DIFF_DIFFER:   return "\xE2\x9C\x97"; /* ✗ */
    case DIFF_LHS_ONLY: return "-";
    case DIFF_RHS_ONLY: return "+";
    }
    return "?";
}

static const char *ansi_open(diff_status_t s)
{
    switch (s) {
    case DIFF_MATCH:    return "\x1b[32m"; /* green */
    case DIFF_DIFFER:   return "\x1b[31m"; /* red */
    case DIFF_LHS_ONLY: return "\x1b[33m"; /* yellow */
    case DIFF_RHS_ONLY: return "\x1b[33m"; /* yellow */
    }
    return "";
}

#define ANSI_RESET "\x1b[0m"

/* Truncate a value's canonical bytes for human display. Caller frees. */
static char *summary_value(const struct jcsp_value *v, size_t max_len)
{
    char *full = NULL;
    if (value_to_canonical_string(v, &full) != 0) {
        return NULL;
    }
    size_t len = strlen(full);
    if (len <= max_len) {
        return full;
    }
    /* Truncate, append "...".  Allocate fresh; original full goes free. */
    char *trunc = malloc(max_len + 4);
    if (trunc == NULL) {
        free(full);
        return NULL;
    }
    memcpy(trunc, full, max_len);
    memcpy(trunc + max_len, "...", 4); /* includes NUL */
    free(full);
    return trunc;
}

static int render_text(FILE *out, const struct diff_result *r, bool color)
{
    /* Compute column width once so paths align. */
    size_t max_path = 0;
    for (size_t i = 0; i < r->n; i++) {
        size_t l = strlen(r->records[i].path);
        if (l > max_path) {
            max_path = l;
        }
    }
    /* Cap at 40 to keep the line tidy if a future field has an exotic name. */
    if (max_path > 40) {
        max_path = 40;
    }

    for (size_t i = 0; i < r->n; i++) {
        const struct diff_record *rec = &r->records[i];

        if (color) {
            fprintf(out, "%s%s%s ", ansi_open(rec->status),
                    status_glyph(rec->status), ANSI_RESET);
        } else {
            fprintf(out, "%s ", status_glyph(rec->status));
        }
        fprintf(out, "%-*s  ", (int)max_path, rec->path);

        switch (rec->status) {
        case DIFF_MATCH:
            fputs("(match)", out);
            break;
        case DIFF_DIFFER: {
            char *l = summary_value(rec->lhs, 40);
            char *rs = summary_value(rec->rhs, 40);
            fprintf(out, "(differ; lhs=%s rhs=%s)",
                    l ? l : "?", rs ? rs : "?");
            free(l);
            free(rs);
            break;
        }
        case DIFF_LHS_ONLY: {
            char *l = summary_value(rec->lhs, 60);
            fprintf(out, "(lhs only; lhs=%s)", l ? l : "?");
            free(l);
            break;
        }
        case DIFF_RHS_ONLY: {
            char *rs = summary_value(rec->rhs, 60);
            fprintf(out, "(rhs only; rhs=%s)", rs ? rs : "?");
            free(rs);
            break;
        }
        }
        fputc('\n', out);
    }

    /* Summary line. */
    bool drift = diff_has_drift(r);
    if (color) {
        fprintf(out, "%s", drift ? "\x1b[31m" : "\x1b[32m");
    }
    fprintf(out, "%s: %zu of %zu fields differ "
                 "(matches=%zu differs=%zu lhs_only=%zu rhs_only=%zu)",
            drift ? "DRIFT" : "PARITY",
            r->differs + r->lhs_only + r->rhs_only,
            r->n,
            r->matches, r->differs, r->lhs_only, r->rhs_only);
    if (color) {
        fputs(ANSI_RESET, out);
    }
    fputc('\n', out);

    return 0;
}

/* ------------------------------------------------------------------ */
/* JSON mode (canonical).                                             */
/*                                                                    */
/* Schema (sorted keys):                                              */
/*   {                                                                */
/*     "differs":  <uint>,                                            */
/*     "lhs_only": <uint>,                                            */
/*     "matches":  <uint>,                                            */
/*     "records":  { "<path>": <record-obj>, ... },                   */
/*     "rhs_only": <uint>                                             */
/*   }                                                                */
/* Per-record obj keys depend on status — sorted "lhs" < "rhs" <      */
/* "status":                                                          */
/*   - MATCH/DIFFER: lhs, rhs, status                                 */
/*   - LHS_ONLY:     lhs, status                                      */
/*   - RHS_ONLY:     rhs, status                                      */
/* "records" sub-object keys are diff paths in sorted order, which    */
/* falls out of the merge naturally (both inputs are canonical).      */
/* ------------------------------------------------------------------ */

static const char *status_string(diff_status_t s)
{
    switch (s) {
    case DIFF_MATCH:    return "MATCH";
    case DIFF_DIFFER:   return "DIFFER";
    case DIFF_LHS_ONLY: return "LHS_ONLY";
    case DIFF_RHS_ONLY: return "RHS_ONLY";
    }
    return "UNKNOWN";
}

static int emit_record_value_pair(struct attest_emitter *em, const char *key,
                                  const struct jcsp_value *v)
{
    char *s = NULL;
    if (value_to_canonical_string(v, &s) != 0) {
        return -1;
    }
    int rc = em->ops->key(em->ctx, key);
    if (rc == 0) {
        rc = em->ops->value_string(em->ctx, s);
    }
    free(s);
    return rc;
}

static int emit_record(struct attest_emitter *em, const struct diff_record *rec)
{
    int rc = em->ops->object_open(em->ctx);
    if (rc == 0 && rec->lhs != NULL) {
        rc = emit_record_value_pair(em, "lhs", rec->lhs);
    }
    if (rc == 0 && rec->rhs != NULL) {
        rc = emit_record_value_pair(em, "rhs", rec->rhs);
    }
    if (rc == 0) {
        rc = em->ops->key(em->ctx, "status");
    }
    if (rc == 0) {
        rc = em->ops->value_string(em->ctx, status_string(rec->status));
    }
    if (rc == 0) {
        rc = em->ops->object_close(em->ctx);
    }
    return rc;
}

static int render_json(FILE *out, const struct diff_result *r)
{
    struct jcs_buffer buf;
    struct jcs_canonical_ctx ctx;
    struct attest_emitter em;
    jcs_buffer_init(&buf);
    jcs_canonical_init(&em, &ctx, &buf);

    int rc = em.ops->object_open(em.ctx);
    if (rc == 0) rc = em.ops->key(em.ctx, "differs");
    if (rc == 0) rc = em.ops->value_uint(em.ctx, r->differs);
    if (rc == 0) rc = em.ops->key(em.ctx, "lhs_only");
    if (rc == 0) rc = em.ops->value_uint(em.ctx, r->lhs_only);
    if (rc == 0) rc = em.ops->key(em.ctx, "matches");
    if (rc == 0) rc = em.ops->value_uint(em.ctx, r->matches);
    if (rc == 0) rc = em.ops->key(em.ctx, "records");
    if (rc == 0) rc = em.ops->object_open(em.ctx);

    for (size_t i = 0; rc == 0 && i < r->n; i++) {
        const struct diff_record *rec = &r->records[i];
        rc = em.ops->key(em.ctx, rec->path);
        if (rc == 0) {
            rc = emit_record(&em, rec);
        }
    }

    if (rc == 0) rc = em.ops->object_close(em.ctx);
    if (rc == 0) rc = em.ops->key(em.ctx, "rhs_only");
    if (rc == 0) rc = em.ops->value_uint(em.ctx, r->rhs_only);
    if (rc == 0) rc = em.ops->object_close(em.ctx);

    if (rc == 0) {
        if (fwrite(buf.data, 1, buf.len, out) != buf.len) {
            rc = -1;
        } else if (fputc('\n', out) == EOF) {
            rc = -1;
        }
    }

    jcs_buffer_free(&buf);
    return rc;
}

int diff_render(FILE *out, const struct diff_result *r,
                const diff_render_opts_t *opts)
{
    if (opts->json_mode) {
        return render_json(out, r);
    }
    return render_text(out, r, opts->color);
}
