#pragma once

/*
 * Minimal slash/optparse.h compat header.
 *
 * Upstream spaceinventor/slash ships a real optparse implementation; we don't
 * need any of it at runtime. apm_csh's <apm/csh_api.h> declares
 * `csh_add_node_option(optparse_t *parser, ...)` and a handful of related
 * prototypes, so the typedefs below have to be visible at the point of
 * declaration even though we never define or call those functions ourselves.
 *
 * Symbols stay opaque — anyone who actually links against an APM that uses
 * these would supply the real optparse via csh's slash. We leave the
 * concrete struct shapes to upstream.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct optparse;
typedef struct optparse optparse_t;

struct optparse_opt;
typedef struct optparse_opt optparse_opt_t;

#ifdef __cplusplus
}
#endif
