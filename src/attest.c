/*
 * csh-attest engine implementation.
 *
 * This file currently bundles three concerns that will split out as the
 * project grows:
 *   1. The field table + walker.
 *   2. A non-canonical FILE* emitter (placeholder until JCS lands in
 *      session 4).
 *   3. The kernel.uname adapter (the only adapter so far).
 *
 * Splitting points: emitter goes to attest_emitter.c when JCS lands;
 * adapters go to per-file modules under src/adapters when the second adapter
 * lands. Premature splitting before then is just churn.
 */

#include "attest.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/utsname.h>
#endif

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
        .name = "kernel.uname",
        .emit = attest_adapter_kernel_uname,
        .size_budget = 256, /* uname struct: ~4 fields × ~65 chars. */
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
/* FILE* emitter — non-canonical JSON.                                */
/*                                                                    */
/* Session-3 placeholder. Output is JSON-shaped so a human eye can    */
/* read it, but it is NOT byte-deterministic across runs (key order   */
/* is insertion order, no number normalization, no string escape      */
/* tightness). Session 4 swaps to a JCS-canonical emitter; adapter    */
/* code does not change.                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    FILE *out;
    int depth;
    bool first_in_object[8]; /* Stack — supports up to 8 nested objects. */
} file_emitter_ctx_t;

/*
 * Comma-and-newline insertion before any non-first key inside an object.
 * Centralized so the per-op functions stay short.
 */
static int file_emitter_pre_value(file_emitter_ctx_t *ctx)
{
    if (ctx->depth <= 0) {
        return 0;
    }
    int idx = ctx->depth - 1;
    if (!ctx->first_in_object[idx]) {
        if (fputs(",\n", ctx->out) == EOF) {
            return -1;
        }
    }
    ctx->first_in_object[idx] = false;
    return 0;
}

static int file_emitter_object_open(void *raw)
{
    file_emitter_ctx_t *ctx = raw;
    if (ctx->depth >= (int)(sizeof(ctx->first_in_object) /
                            sizeof(ctx->first_in_object[0]))) {
        return -1;
    }
    ctx->first_in_object[ctx->depth] = true;
    ctx->depth++;
    if (fputs("{\n", ctx->out) == EOF) {
        return -1;
    }
    return 0;
}

static int file_emitter_object_close(void *raw)
{
    file_emitter_ctx_t *ctx = raw;
    if (ctx->depth <= 0) {
        return -1;
    }
    ctx->depth--;
    if (fputs("\n}", ctx->out) == EOF) {
        return -1;
    }
    return 0;
}

static int file_emitter_key(void *raw, const char *key)
{
    file_emitter_ctx_t *ctx = raw;
    if (file_emitter_pre_value(ctx) < 0) {
        return -1;
    }
    if (fprintf(ctx->out, "  \"%s\": ", key) < 0) {
        return -1;
    }
    return 0;
}

static int file_emitter_value_string(void *raw, const char *value)
{
    file_emitter_ctx_t *ctx = raw;
    /*
     * The FILE* emitter is for human-readable debug output, NOT canonical
     * bytes — it does no escape work. Adapters that route their bytes
     * through the canonical emitter (jcs.c) get RFC 8785 §3.2.2.2 escapes
     * for free.
     */
    if (fprintf(ctx->out, "\"%s\"", value) < 0) {
        return -1;
    }
    return 0;
}

static int file_emitter_value_uint(void *raw, uint64_t value)
{
    file_emitter_ctx_t *ctx = raw;
    if (fprintf(ctx->out, "%" PRIu64, value) < 0) {
        return -1;
    }
    return 0;
}

static int file_emitter_value_bytes_hex(void *raw, const uint8_t *bytes,
                                        size_t len)
{
    file_emitter_ctx_t *ctx = raw;
    if (fputc('"', ctx->out) == EOF) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        if (fprintf(ctx->out, "%02x", bytes[i]) < 0) {
            return -1;
        }
    }
    if (fputc('"', ctx->out) == EOF) {
        return -1;
    }
    return 0;
}

static const struct attest_emitter_ops file_emitter_ops = {
    .object_open = file_emitter_object_open,
    .object_close = file_emitter_object_close,
    .key = file_emitter_key,
    .value_string = file_emitter_value_string,
    .value_uint = file_emitter_value_uint,
    .value_bytes_hex = file_emitter_value_bytes_hex,
};

/*
 * The ctx is allocated by the caller via attest_emitter_init_file but stored
 * in a static so the emitter struct itself stays a 2-word handle. One
 * emitter per process is sufficient for v1 — attest --emit is sequential.
 *
 * If concurrent emits ever land (e.g., for a streaming attest --remote
 * server-side path), this becomes a heap allocation owned by struct
 * attest_emitter.
 */
static file_emitter_ctx_t g_file_emitter_ctx;

void attest_emitter_init_file(struct attest_emitter *em, FILE *out)
{
    g_file_emitter_ctx = (file_emitter_ctx_t){.out = out, .depth = 0};
    em->ops = &file_emitter_ops;
    em->ctx = &g_file_emitter_ctx;
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

/* ------------------------------------------------------------------ */
/* Adapter: kernel.uname.                                             */
/*                                                                    */
/* uname() is in POSIX so it works on Linux *and* macOS for the dev   */
/* build. The real kernel.build_id (GNU build-id ELF note) lands in   */
/* a later session alongside hex-encoding helpers.                    */
/* ------------------------------------------------------------------ */

int attest_adapter_kernel_uname(struct attest_emitter *em)
{
#if defined(__linux__) || defined(__APPLE__)
    struct utsname u;
    if (uname(&u) != 0) {
        return -1; /* E001-equivalent until error codes formalize. */
    }

    int rc = em->ops->object_open(em->ctx);
    if (rc < 0) {
        return rc;
    }

    /* Order is alphabetical so JCS canonicalization in session 4 is a no-op
     * for this adapter — keys are already sorted. */
    static const struct {
        const char *key;
        size_t offset;
    } fields[] = {
        {"machine", offsetof(struct utsname, machine)},
        {"release", offsetof(struct utsname, release)},
        {"sysname", offsetof(struct utsname, sysname)},
        {"version", offsetof(struct utsname, version)},
    };

    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        rc = em->ops->key(em->ctx, fields[i].key);
        if (rc < 0) {
            return rc;
        }
        const char *value = (const char *)&u + fields[i].offset;
        rc = em->ops->value_string(em->ctx, value);
        if (rc < 0) {
            return rc;
        }
    }

    return em->ops->object_close(em->ctx);
#else
    (void)em;
    return -1;
#endif
}
