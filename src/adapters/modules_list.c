/*
 * modules.list adapter implementation.
 *
 * Two functions:
 *   - emit_modules_list_from_stream: testable core. Takes an open FILE*
 *     of /proc/modules content + a sysfs root, emits the canonical array.
 *   - attest_adapter_modules_list: production wrapper. Opens
 *     /proc/modules + uses /sys/module on Linux; on non-Linux dev builds
 *     it emits an empty array (deterministic, walker-friendly — macOS
 *     isn't a v1 target so producing zero entries is OK).
 */

#include "modules_list.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* String list — single-malloc-per-name, sortable.                    */
/* ------------------------------------------------------------------ */

struct name_list {
    char **items;
    size_t n;
    size_t cap;
};

static int name_list_push(struct name_list *l, const char *name, size_t len)
{
    if (l->n == l->cap) {
        size_t new_cap = l->cap ? l->cap * 2 : 16;
        char **new_items = realloc(l->items, new_cap * sizeof(char *));
        if (new_items == NULL) {
            return -1;
        }
        l->items = new_items;
        l->cap = new_cap;
    }
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, name, len);
    copy[len] = '\0';
    l->items[l->n++] = copy;
    return 0;
}

static void name_list_free(struct name_list *l)
{
    for (size_t i = 0; i < l->n; i++) {
        free(l->items[i]);
    }
    free(l->items);
    l->items = NULL;
    l->n = 0;
    l->cap = 0;
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ------------------------------------------------------------------ */
/* Read first whitespace-delimited token from a /proc/modules line.   */
/* The kernel format is well-defined: name is always token #1.        */
/* ------------------------------------------------------------------ */

static int extract_name(const char *line, const char **out_start, size_t *out_len)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p == '\0' || *p == '\n') {
        return -1; /* blank line — caller skips */
    }
    const char *start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n') {
        p++;
    }
    /*
     * Reject pathologically long names (>= 256 chars). Real kernel kmod
     * names are <64 chars; anything longer is corrupted input.
     */
    size_t len = (size_t)(p - start);
    if (len == 0 || len >= 256) {
        return -1;
    }
    *out_start = start;
    *out_len = len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Read srcversion from <sysfs_root>/<name>/srcversion — if present.  */
/* On any error (file missing, IO, oversize) returns "" so the output */
/* shape stays uniform.                                               */
/* ------------------------------------------------------------------ */

static int read_srcversion(const char *sysfs_root, const char *name,
                           char *out, size_t out_size)
{
    out[0] = '\0';
    /*
     * Path budget: sysfs_root + "/" + name + "/srcversion" + NUL.
     * Reasonable cap: 4 KB (Linux PATH_MAX).
     */
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%s/srcversion",
                     sysfs_root, name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return -1;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        /* Built-in kmod or missing — empty string is the canonical "absent"
         * representation. */
        return 0;
    }
    /*
     * srcversion is a 32-char hex hash followed by a newline. Cap at
     * out_size - 1 to leave room for NUL.  Trim any trailing whitespace
     * (spaces, newlines) so the JSON value is the bare hash.
     */
    size_t r = fread(out, 1, out_size - 1, f);
    fclose(f);
    out[r] = '\0';
    while (r > 0 && (out[r - 1] == '\n' || out[r - 1] == '\r' ||
                     out[r - 1] == ' ' || out[r - 1] == '\t')) {
        out[--r] = '\0';
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Streaming emitter.                                                 */
/* ------------------------------------------------------------------ */

int emit_modules_list_from_stream(FILE *proc_modules,
                                  const char *sysfs_module_root,
                                  struct attest_emitter *em)
{
    if (proc_modules == NULL || em == NULL || sysfs_module_root == NULL) {
        return -1;
    }

    struct name_list names = {0};
    char line[1024];
    int rc = -1;

    while (fgets(line, sizeof(line), proc_modules) != NULL) {
        const char *start;
        size_t len;
        if (extract_name(line, &start, &len) < 0) {
            continue; /* blank or pathological — skip */
        }
        if (name_list_push(&names, start, len) < 0) {
            goto cleanup;
        }
    }

    qsort(names.items, names.n, sizeof(char *), name_cmp);

    rc = em->ops->array_open(em->ctx);
    if (rc < 0) {
        goto cleanup;
    }
    for (size_t i = 0; i < names.n; i++) {
        char srcversion[128];
        if (read_srcversion(sysfs_module_root, names.items[i],
                            srcversion, sizeof(srcversion)) < 0) {
            rc = -1;
            goto cleanup;
        }
        rc = em->ops->object_open(em->ctx);
        if (rc < 0) goto cleanup;
        /* "name" < "srcversion" alphabetically — JCS sort order. */
        rc = em->ops->key(em->ctx, "name");
        if (rc < 0) goto cleanup;
        rc = em->ops->value_string(em->ctx, names.items[i]);
        if (rc < 0) goto cleanup;
        rc = em->ops->key(em->ctx, "srcversion");
        if (rc < 0) goto cleanup;
        rc = em->ops->value_string(em->ctx, srcversion);
        if (rc < 0) goto cleanup;
        rc = em->ops->object_close(em->ctx);
        if (rc < 0) goto cleanup;
    }
    rc = em->ops->array_close(em->ctx);

cleanup:
    name_list_free(&names);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Production adapter.                                                */
/* ------------------------------------------------------------------ */

int attest_adapter_modules_list(struct attest_emitter *em)
{
#ifdef __linux__
    FILE *f = fopen("/proc/modules", "r");
    if (f == NULL) {
        /*
         * /proc not available (chroot, container without /proc mount).
         * Emit an empty array — deterministic, walker-friendly, signals
         * "no kmods visible" without aborting the manifest.
         */
        int rc = em->ops->array_open(em->ctx);
        if (rc == 0) {
            rc = em->ops->array_close(em->ctx);
        }
        return rc;
    }
    int rc = emit_modules_list_from_stream(f, "/sys/module", em);
    fclose(f);
    return rc;
#else
    /*
     * Non-Linux dev build (macOS): no /proc/modules concept. Emit empty
     * array so attest_emit() walks cleanly through this row.
     */
    int rc = em->ops->array_open(em->ctx);
    if (rc == 0) {
        rc = em->ops->array_close(em->ctx);
    }
    return rc;
#endif
}
