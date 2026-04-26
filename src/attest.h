#pragma once

/*
 * csh-attest engine — table-driven introspection per design doc 2B.
 *
 * The engine is data-oriented: a static array of attest_field_t describes
 * every field in the manifest. Each row pairs a JSON-output name with the
 * adapter callback that emits its value. The walker (attest_emit) iterates
 * the table, handing each adapter a struct attest_emitter the adapter writes
 * into.
 *
 * The emitter is a vtable so the same adapter code can drive different
 * outputs:
 *   - production:  FILE* JSON writer (session 3, non-canonical placeholder)
 *   - production:  JCS canonicalizer (session 4 swap-in)
 *   - tests:       a recording emitter that captures call sequences
 *
 * Adapter authors only see the emitter's API; they do not know whether the
 * bytes go to stdout, a buffer, a SHA-256 hash function, or a test recorder.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Determinism class. Used by the walker (eventually) to filter what enters
 * the canonical-hash payload vs. what is informational only. Session 3 stores
 * the value but does not yet act on it.
 */
typedef enum {
    DET_STABLE,   /* Same value across runs and reboots. Hashed. */
    DET_RACY,     /* May vary mid-run; require single snapshot. Hashed. */
    DET_VOLATILE, /* E.g., attest_time_utc. NOT hashed; informational only. */
} det_class_t;

/* Forward declaration; full definition further down. */
struct attest_emitter;

/*
 * Adapter callback signature. The adapter calls the emitter's APIs to
 * produce its field's value (a scalar, an object, or an array). Returns 0 on
 * success or a negative E0xx introspection error code (E001-E099 range,
 * design doc 2D).
 */
typedef int (*attest_emit_fn)(struct attest_emitter *em);

/*
 * Per-field row in the introspection table. Keep this small — many rows in
 * a single cache line is the point of the data-oriented design.
 */
typedef struct {
    const char *name;          /* JSON field name, e.g. "kernel.uname". */
    attest_emit_fn emit;       /* Adapter callback. */
    size_t size_budget;        /* Hard cap in bytes (design doc 1F). */
    bool required;             /* If true, adapter failure aborts emit. */
    det_class_t determinism;   /* Determinism class (filtering hint). */
} attest_field_t;

/*
 * Field table. Defined in attest.c; tests can override by linking their own.
 */
extern const attest_field_t attest_fields[];
extern const size_t attest_fields_count;

/*
 * Emitter ops vtable.
 *
 * All ops return 0 on success, negative on failure (e.g., write error or, in
 * the canonical emitter, a JCS rule violation such as out-of-order key). The
 * walker propagates failures up to attest_emit's return value.
 *
 * `array_open` / `array_close` are intentionally absent from session 4 — no
 * adapter yet needs them. They land alongside the modules.list adapter.
 */
struct attest_emitter_ops {
    int (*object_open)(void *ctx);
    int (*object_close)(void *ctx);
    int (*key)(void *ctx, const char *key);
    int (*value_string)(void *ctx, const char *value);
    int (*value_uint)(void *ctx, uint64_t value);
    int (*value_bytes_hex)(void *ctx, const uint8_t *bytes, size_t len);
};

/*
 * Emitter handle. The walker creates this on the stack, passes a pointer to
 * each adapter. Adapters do not allocate.
 */
struct attest_emitter {
    const struct attest_emitter_ops *ops;
    void *ctx;
};

/*
 * Initialize a non-canonical FILE* emitter. Writes JSON-shaped output. Will
 * be replaced in session 4 by a JCS-canonical emitter that hashes through
 * libsodium. Adapter code does not change when that happens.
 */
void attest_emitter_init_file(struct attest_emitter *em, FILE *out);

/*
 * Walk the field table, emitting the manifest envelope into `em`. Returns 0
 * on success or the first non-zero return from a required adapter (or from
 * the emitter itself).
 */
int attest_emit(struct attest_emitter *em);

/*
 * kernel.uname adapter — captures the running kernel release string via the
 * uname() syscall. Linux-only in v1; on other systems the adapter returns
 * ENOSYS-equivalent (-1) and the walker propagates per the field's
 * `required` setting.
 *
 * Exposed in the header so tests can call it directly without going through
 * the full table walker.
 */
int attest_adapter_kernel_uname(struct attest_emitter *em);

#ifdef __cplusplus
}
#endif
