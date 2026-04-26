/*
 * kernel.uname adapter — captures the running kernel release info via the
 * uname() syscall.
 *
 * uname() is POSIX so this works on Linux (the production target) AND
 * macOS (the dev target — "compile-check only" per the design doc but
 * also runs the unit tests). Real kernel.build_id (GNU build-id ELF note)
 * is a separate adapter that lands in a later session.
 *
 * Moved out of attest.c in session 7 alongside modules.list landing —
 * the table-driven engine pattern (design doc 2B) intends one C file
 * per adapter, with attest.c holding only the engine + walker + table.
 */

#include "attest.h"

#include <stddef.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/utsname.h>
#endif

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

    /* Order is alphabetical so JCS canonicalization is a no-op for this
     * adapter — keys arrive already sorted. */
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
