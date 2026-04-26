#pragma once

/*
 * csh-attest internal header.
 *
 * Stays small in session 1-2. The introspection table-driven engine (per
 * design doc 2B `attest_field_t`) lands in session 3 alongside the first
 * adapters.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the APM. Invoked from upstream libmain (apm_csh) via the weak
 * apm_init hook. Decoupled from apm_init() so the unit tests can call it
 * directly without dragging in the full apm_csh static library.
 *
 * Returns 0 on success, non-zero on failure (csh treats non-zero as fatal and
 * aborts the load).
 */
int csh_attest_init(void);

#ifdef __cplusplus
}
#endif
