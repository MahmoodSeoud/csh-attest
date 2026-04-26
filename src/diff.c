/*
 * attest-diff structural comparison.
 *
 * Two-pointer merge across the sorted key sets of two top-level objects.
 * O(n + m). Per-pair value comparison delegates to jcsp_value_equals
 * (which itself recurses into nested objects).
 */

#include "diff.h"

#include <stdlib.h>
#include <string.h>

static int diff_record_push(struct diff_result *r,
                            size_t *cap,
                            const char *path,
                            diff_status_t status,
                            const struct jcsp_value *lhs,
                            const struct jcsp_value *rhs)
{
    if (r->n == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 8;
        struct diff_record *new_arr = realloc(
            r->records, new_cap * sizeof(struct diff_record));
        if (new_arr == NULL) {
            return -1;
        }
        r->records = new_arr;
        *cap = new_cap;
    }
    r->records[r->n] = (struct diff_record){
        .path = path,
        .status = status,
        .lhs = lhs,
        .rhs = rhs,
    };
    r->n++;
    switch (status) {
    case DIFF_MATCH:    r->matches++;  break;
    case DIFF_DIFFER:   r->differs++;  break;
    case DIFF_LHS_ONLY: r->lhs_only++; break;
    case DIFF_RHS_ONLY: r->rhs_only++; break;
    }
    return 0;
}

int attest_diff(const struct jcsp_value *lhs,
                const struct jcsp_value *rhs,
                struct diff_result *out)
{
    memset(out, 0, sizeof(*out));

    if (lhs->type != JCSP_OBJECT || rhs->type != JCSP_OBJECT) {
        return -1;
    }

    size_t cap = 0;
    size_t i = 0, j = 0;

    while (i < lhs->u.object.n && j < rhs->u.object.n) {
        const struct jcsp_member *lm = &lhs->u.object.members[i];
        const struct jcsp_member *rm = &rhs->u.object.members[j];
        int cmp = strcmp(lm->key, rm->key);

        if (cmp == 0) {
            diff_status_t status = jcsp_value_equals(&lm->value, &rm->value)
                ? DIFF_MATCH : DIFF_DIFFER;
            if (diff_record_push(out, &cap, lm->key, status,
                                 &lm->value, &rm->value) < 0) {
                return -1;
            }
            i++;
            j++;
        } else if (cmp < 0) {
            if (diff_record_push(out, &cap, lm->key, DIFF_LHS_ONLY,
                                 &lm->value, NULL) < 0) {
                return -1;
            }
            i++;
        } else {
            if (diff_record_push(out, &cap, rm->key, DIFF_RHS_ONLY,
                                 NULL, &rm->value) < 0) {
                return -1;
            }
            j++;
        }
    }

    while (i < lhs->u.object.n) {
        const struct jcsp_member *lm = &lhs->u.object.members[i++];
        if (diff_record_push(out, &cap, lm->key, DIFF_LHS_ONLY,
                             &lm->value, NULL) < 0) {
            return -1;
        }
    }
    while (j < rhs->u.object.n) {
        const struct jcsp_member *rm = &rhs->u.object.members[j++];
        if (diff_record_push(out, &cap, rm->key, DIFF_RHS_ONLY,
                             NULL, &rm->value) < 0) {
            return -1;
        }
    }

    return 0;
}

void diff_result_free(struct diff_result *r)
{
    if (r == NULL) {
        return;
    }
    free(r->records);
    memset(r, 0, sizeof(*r));
}

bool diff_has_drift(const struct diff_result *r)
{
    return r->differs > 0 || r->lhs_only > 0 || r->rhs_only > 0;
}
