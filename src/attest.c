/*
 * csh-attest engine — field table + walker + the trivial schema_version
 * adapter. All other adapters live under src/adapters/ per design doc 2B.
 *
 * The non-canonical FILE* emitter that lived here through sessions 3-6 was
 * dead code (no caller; superseded by the JCS canonical emitter). Removed
 * in session 7 alongside the adapter split.
 */

#include "attest.h"

/* ------------------------------------------------------------------ */
/* Field table.                                                       */
/*                                                                    */
/* MUST be authored in JCS-sorted order (RFC 8785 §3.2.3, key sort   */
/* by UTF-16 code-unit order — equivalent to byte order for ASCII).   */
/* The canonical emitter (jcs.c) enforces this at runtime; tests fail */
/* loudly if a row is misplaced.                                      */
/* ------------------------------------------------------------------ */

static int adapter_schema_version(struct attest_emitter *em);

const attest_field_t attest_fields[] = {
    {
        .name = "etc.merkle",
        .emit = attest_adapter_etc_merkle,
        .size_budget = 32, /* design doc 1F: 32 B (root only). */
        .required = true,
        .determinism = DET_STABLE,
    },
    {
        /* "kernel.build_id" sorts before "kernel.uname" because at byte
         * index 7 the period (0x2E) is followed by 'b' (0x62) here vs. 'u'
         * (0x75) there — JCS-canonical order is byte-wise. */
        .name = "kernel.build_id",
        .emit = attest_adapter_kernel_build_id,
        .size_budget = 64, /* design doc 1F: 64 B. */
        .required = true,
        .determinism = DET_STABLE,
    },
    {
        .name = "kernel.uname",
        .emit = attest_adapter_kernel_uname,
        .size_budget = 256, /* uname struct: ~4 fields × ~65 chars. */
        .required = true,
        .determinism = DET_STABLE,
    },
    {
        .name = "modules.list",
        .emit = attest_adapter_modules_list,
        .size_budget = 8 * 1024, /* design doc 1F: 8 KB cap. */
        .required = true,
        .determinism = DET_STABLE,
    },
    {
        .name = "schema_version",
        .emit = adapter_schema_version,
        .size_budget = 16,  /* "0.1.0" plus quotes plus headroom. */
        .required = true,
        .determinism = DET_STABLE,
    },
};

const size_t attest_fields_count =
    sizeof(attest_fields) / sizeof(attest_fields[0]);

static int adapter_schema_version(struct attest_emitter *em)
{
    return em->ops->value_string(em->ctx, "0.1.0");
}

/* ------------------------------------------------------------------ */
/* Walker.                                                            */
/* ------------------------------------------------------------------ */

int attest_emit(struct attest_emitter *em)
{
    int rc;

    rc = em->ops->object_open(em->ctx);
    if (rc < 0) {
        return rc;
    }

    for (size_t i = 0; i < attest_fields_count; i++) {
        const attest_field_t *f = &attest_fields[i];

        rc = em->ops->key(em->ctx, f->name);
        if (rc < 0) {
            return rc;
        }

        rc = f->emit(em);
        if (rc != 0) {
            /*
             * 1D atomic-emit contract: any required-field failure aborts the
             * whole manifest. Optional-field failure is currently propagated
             * too — a future session can introduce a SKIP_OK return code
             * that lets !required fields drop out cleanly.
             */
            if (f->required) {
                return rc;
            }
        }
    }

    return em->ops->object_close(em->ctx);
}
