#pragma once

/*
 * attest-diff structural comparison over two parsed JCS-canonical
 * manifests.
 *
 * Operates at the top-level field set only — nested objects compare as
 * opaque values (DIFFER if any sub-field differs). Per design doc Diagram
 * 1, top-level keys are dotted names like `kernel.build_id`,
 * `modules.list`, `/etc.merkle` (the dots/slashes are part of the name,
 * not path segments) — recursive descent is not what callers want here.
 *
 * Both inputs must be JCS-canonical objects (i.e., produced by the
 * jcs.c emitter or the equivalent test tooling). Sortedness of keys lets
 * us run a linear two-pointer merge instead of an N×M scan.
 *
 * Lifetime: diff_result borrows pointers into both input trees — `path`
 * points into one tree's key buffer, `lhs`/`rhs` point at value subtrees.
 * Caller must keep both jcsp_value trees alive until diff_result_free.
 */

#include <stdbool.h>
#include <stddef.h>

#include "jcs_parse.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DIFF_MATCH,       /* present on both sides, structurally equal */
    DIFF_DIFFER,      /* present on both sides, values differ */
    DIFF_LHS_ONLY,    /* present on lhs only */
    DIFF_RHS_ONLY,    /* present on rhs only */
} diff_status_t;

struct diff_record {
    const char *path;             /* borrowed from one of the input trees */
    diff_status_t status;
    const struct jcsp_value *lhs; /* NULL when status == DIFF_RHS_ONLY */
    const struct jcsp_value *rhs; /* NULL when status == DIFF_LHS_ONLY */
};

struct diff_result {
    struct diff_record *records;  /* sorted by path (input is canonical) */
    size_t n;
    /* Tallies for the renderer summary line. */
    size_t matches;
    size_t differs;
    size_t lhs_only;
    size_t rhs_only;
};

/*
 * Compute the structural diff. Both inputs must be JCSP_OBJECT — anything
 * else returns -1. Caller-owned `out` is populated; on failure it is left
 * in a state safe for diff_result_free.
 *
 * Returns 0 on success, -1 on type mismatch or allocation failure.
 */
int attest_diff(const struct jcsp_value *lhs,
                const struct jcsp_value *rhs,
                struct diff_result *out);

void diff_result_free(struct diff_result *r);

/*
 * True iff the diff contains any non-MATCH record.  Used by the renderer
 * to choose its exit code.
 */
bool diff_has_drift(const struct diff_result *r);

#ifdef __cplusplus
}
#endif
