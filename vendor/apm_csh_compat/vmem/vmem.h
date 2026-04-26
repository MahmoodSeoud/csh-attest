#pragma once

/*
 * Minimal vmem compat header for libapm_csh.
 *
 * libapm_csh's src/apm.c references `vmem_t` (as the type of the bracket
 * symbols `__start_vmem` / `__stop_vmem`) and calls `vmem_add` outside
 * the `APM_HAVE_PARAM` gate that protects its real `<vmem/vmem.h>`
 * include. Without a typedef + prototype visible at apm.c compile time
 * the build fails under -Werror with:
 *
 *   error: unknown type name 'vmem_t'
 *   error: implicit declaration of function 'vmem_add'
 *
 * Upstream callers fix this by always providing libparam (which pulls in
 * libvmem); we don't link libparam — csh's main binary supplies vmem_add
 * at dlopen time and the runtime guard `&__start_vmem != &__stop_vmem`
 * short-circuits because we have no `vmem` ELF section.
 *
 * vmem_t stays incomplete here: the only operations apm.c performs are
 * &-of and pointer comparison, both legal on incomplete types. csh's
 * full vmem.h defines the real layout; we never need to look inside.
 *
 * Exposed via vendor/apm_csh_compat through the slash compat dependency
 * (vendor/slash + vendor/apm_csh_compat both flow into the slash dep
 * partial-include passed to apm_csh).
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vmem vmem_t;

void vmem_add(vmem_t *start, vmem_t *stop);

#ifdef __cplusplus
}
#endif
