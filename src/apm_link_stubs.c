/*
 * Link-time stubs for symbols apm_csh's upstream libmain references but
 * neither csh-attest's .so nor its test binaries otherwise resolve.
 *
 * `vmem_add` is called from libapm_csh::libmain only when the `vmem` ELF
 * section is non-empty (`&__start_vmem != &__stop_vmem`). csh-attest has
 * no vmem section, so the runtime guard short-circuits — but the linker
 * still requires the symbol. Alpine + GCC default to `-Wl,--no-undefined`
 * for shared_library targets; Ubuntu does too. Production csh's main
 * binary provides the real implementation; the stub here is never called
 * because the guard short-circuits, but it satisfies link-time.
 *
 * Marked `weak` so that if csh's real `vmem_add` is somehow visible at
 * link time (or via RTLD_GLOBAL at dlopen), it overrides the stub.
 *
 * `slash_list_add` is referenced weakly by libapm_csh and resolved at
 * dlopen against csh; in tests/test_init.c the recording stub overrides
 * it. No need to define it here.
 *
 * Linux-only — added to csh_attest_sources / csh_attest_test_sources
 * inside the `if is_linux` blocks. macOS doesn't link libapm_csh so this
 * file isn't reached there.
 */

#include <vmem/vmem.h>

__attribute__((weak)) void vmem_add(vmem_t *start, vmem_t *stop)
{
    (void)start;
    (void)stop;
}
