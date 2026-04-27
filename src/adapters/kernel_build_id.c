/*
 * kernel.build_id adapter implementation. See kernel_build_id.h for the
 * algorithm + cross-platform contract.
 *
 * The note-walking is delegated to elf_note_walk.c — the same parser
 * also drives binaries.list (where it walks PT_NOTE segments of userspace
 * ELFs). /sys/kernel/notes is already the .notes section verbatim, so
 * this adapter is just a thin file-slurp + walker wrapper.
 */

#include "kernel_build_id.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attest.h"
#include "elf_note_walk.h"

/*
 * Compile-time check: kernel_build_id.h's local constant must match the
 * shared elf_note_walk.h cap. If they ever drift, the build catches it
 * before kernel manifests start silently truncating SHA-256 build-ids.
 */
_Static_assert(KERNEL_BUILD_ID_MAX_BYTES == ELF_BUILD_ID_MAX_BYTES,
               "kernel and userspace build-id caps must match");

int kernel_build_id_extract(const uint8_t *bytes, size_t len,
                            uint8_t *out, size_t *out_len)
{
    return elf_note_walk_find_buildid(bytes, len, out, out_len);
}

/*
 * Slurp `path` into a heap buffer. /sys/kernel/notes is small (typically
 * <1 KB on a modern kernel); 64 KB caps memory in case of a synthetic
 * giant file and is well above any realistic .notes section size.
 */
static int slurp(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    enum { CAP = 64u * 1024u };
    uint8_t *buf = malloc(CAP);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    size_t total = 0;
    while (total < CAP) {
        size_t r = fread(buf + total, 1, CAP - total, f);
        if (r == 0) {
            break;
        }
        total += r;
    }
    int err = ferror(f);
    fclose(f);
    if (err) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = total;
    return 0;
}

int kernel_build_id_emit_from_path(struct attest_emitter *em, const char *path)
{
    uint8_t build_id[KERNEL_BUILD_ID_MAX_BYTES];
    size_t build_id_len = 0;

    uint8_t *bytes = NULL;
    size_t len = 0;
    if (slurp(path, &bytes, &len) == 0) {
        if (kernel_build_id_extract(bytes, len, build_id, &build_id_len) != 0) {
            build_id_len = 0;
        }
        free(bytes);
    }
    /* On Linux without /sys/kernel/notes, or on non-Linux dev, build_id_len
     * stays 0 and the emitter writes "" — deterministic placeholder. */
    return em->ops->value_bytes_hex(em->ctx, build_id, build_id_len);
}

int attest_adapter_kernel_build_id(struct attest_emitter *em)
{
    return kernel_build_id_emit_from_path(em, "/sys/kernel/notes");
}
