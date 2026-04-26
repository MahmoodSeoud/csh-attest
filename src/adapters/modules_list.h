#pragma once

/*
 * modules.list adapter — sorted JCS array of {name, srcversion} objects
 * describing every entry in /proc/modules.
 *
 * Production path: read /proc/modules (one line per loaded kmod), look up
 * srcversion at /sys/module/<name>/srcversion, emit canonical array.
 *
 * Test path: emit_modules_list_from_stream takes an arbitrary FILE* +
 * sysfs root, so unit tests on macOS can inject synthetic data via
 * fmemopen + a tmp directory.
 *
 * Per design doc 1F the modules.list field has an 8 KB size budget. The
 * adapter does not enforce it directly — the engine does, in a future
 * session that wires the size_budget column of the field table.
 *
 * Ordering: module names are sorted alphabetically (memcmp), so the
 * output is JCS-canonical with no extra sort work in the emitter.
 *
 * Missing srcversion: built-in kmods don't expose /sys/module/<name>/
 * srcversion (only loadable modules do). The adapter emits an empty
 * string in that case so the object shape stays uniform — diff sees the
 * same key set across hosts and only the values differ.
 */

#include "attest.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Test-friendly helper. `proc_modules` is an open stream of /proc/modules-
 * shaped content (each line: `<name> <size> <refcnt> <deps> <state> <addr>`,
 * leading whitespace tolerated, blank lines tolerated). `sysfs_module_root`
 * is the path under which `<name>/srcversion` files live (e.g.,
 * "/sys/module").
 *
 * Caller drives the emitter; this function emits exactly one array_open
 * + N object pairs + array_close. Returns 0 on success, -1 on parse,
 * allocation, or emitter failure.
 */
int emit_modules_list_from_stream(FILE *proc_modules,
                                  const char *sysfs_module_root,
                                  struct attest_emitter *em);

#ifdef __cplusplus
}
#endif
