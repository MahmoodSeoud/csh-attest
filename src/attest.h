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
 * `array_open` / `array_close` are optional: the canonical emitter
 * (jcs.c) implements them and uses scope-tracking to insert commas between
 * elements; debug emitters may leave them NULL if no adapter routed through
 * them emits arrays.
 */
struct attest_emitter_ops {
    int (*object_open)(void *ctx);
    int (*object_close)(void *ctx);
    int (*array_open)(void *ctx);
    int (*array_close)(void *ctx);
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
 * Walk the field table, emitting the manifest envelope into `em`. Returns 0
 * on success or the first non-zero return from a required adapter (or from
 * the emitter itself).
 */
int attest_emit(struct attest_emitter *em);

/*
 * Adapter prototypes. Implementations live in src/adapters/<name>.c per
 * the design doc 2B "table-driven introspection" pattern. Exposed here
 * (rather than per-adapter headers) so the field table in attest.c has
 * one canonical place to look up callbacks AND so unit tests can call
 * any adapter directly without going through the walker.
 *
 * - kernel.build_id: GNU build-id ELF note from /sys/kernel/notes. The
 *   cryptographic identity of the kernel image — strictly stronger than
 *   kernel.uname for parity attestation. On non-Linux dev or when the
 *   notes file is missing, emits an empty string (deterministic).
 * - kernel.uname: POSIX uname(). Works on Linux (production) + macOS
 *   (compile-check dev target).
 * - modules.list: Linux /proc/modules + /sys/module/<name>/srcversion.
 *   On non-Linux dev builds it emits an empty array (deterministic
 *   placeholder; macOS isn't a v1 target).
 * - etc.merkle: SHA-256 root over an allowlist of /etc paths. Works on
 *   any Unix; on macOS the allowlisted paths usually don't exist so
 *   the result is the merkle of all-empty content (still deterministic).
 */
int attest_adapter_kernel_build_id(struct attest_emitter *em);
int attest_adapter_kernel_uname(struct attest_emitter *em);
int attest_adapter_modules_list(struct attest_emitter *em);
int attest_adapter_etc_merkle(struct attest_emitter *em);

#ifdef __cplusplus
}
#endif
