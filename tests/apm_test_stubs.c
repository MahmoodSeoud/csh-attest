/*
 * Link-time stubs for symbols apm_csh's upstream libmain references but
 * test binaries don't otherwise resolve.
 *
 * `vmem_add` is called from libapm_csh::libmain only when the `vmem` ELF
 * section is non-empty (`&__start_vmem != &__stop_vmem`). csh-attest has
 * no vmem section, so the runtime guard short-circuits — but the linker
 * still requires the symbol to be defined. Production csh's main binary
 * provides the real implementation; here we provide a no-op so the
 * cmocka test binaries link.
 *
 * `slash_list_add` is also referenced (weak), but tests/test_init.c
 * provides a recording stub that the libmain walker calls. Tests that
 * don't override it leave it weak/NULL and the walker skips the section.
 *
 * Linux-only — gated in tests/meson.build alongside the apm_csh dep.
 */

#include <vmem/vmem.h>

void vmem_add(vmem_t *start, vmem_t *stop)
{
    (void)start;
    (void)stop;
}
