#pragma once

/*
 * csh-attest internal header.
 *
 * Stays small in session 1-2. The introspection table-driven engine (per
 * design doc 2B `attest_field_t`) lands in session 3 alongside the first
 * adapters.
 */

#include <stdio.h>

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

/*
 * Driver for the `attest-diff` command. Decoupled from the slash callback
 * so unit tests can exercise it without faking a `struct slash`.
 *
 * argv layout: argv[0] is the command name (ignored); positional args are
 * <lhs.json> and <rhs.json>; flags are `--json` and `--no-color`.
 *
 * Returns the design-doc shell exit code (NOT a SLASH_E* value):
 *   0 — parity (no drift)
 *   1 — drift detected
 *   2 — usage error, file load failure, or non-canonical JSON input
 *
 * The slash callback in csh_attest.c forwards this return value verbatim
 * so `csh -c "attest-diff ..."` exits with the same code.
 */
int attest_diff_run(int argc, char **argv, FILE *out, FILE *err);

/*
 * Driver for the `attest --verify` command. Parses a signed envelope
 * produced by `attest --sign`, extracts the inner canonical manifest,
 * and verifies the Ed25519 signature with the supplied public key.
 *
 * argv layout: argv[0] is the command name (ignored); argv[1] is the
 * Ed25519 public key file (32 raw bytes); argv[2] is the path to the
 * signed JSON envelope.
 *
 * Returns the design-doc shell exit code (NOT a SLASH_E* value):
 *   0 — signature valid (manifest authentic)
 *   1 — signature invalid (tampered manifest or wrong public key)
 *   2 — usage error, file load failure, malformed envelope
 *
 * On exit 0, no output is written to `out` — verification is a pass/fail
 * gate, not a renderer. On exit 1 a single E201 line is written to `err`.
 */
int attest_verify_run(int argc, char **argv, FILE *out, FILE *err);

/*
 * Render the `attest --help` block. Lists the four subcommands, the env
 * vars (ATTEST_CSP_PORT / ATTEST_CSP_TIMEOUT_MS), and the design-doc exit
 * codes (0/1/2/3). Used by the slash dispatch's `--help` / `-h` branch
 * and by tests/test_help.c. Always writes to `out`; never returns an
 * error.
 */
void attest_print_help(FILE *out);

#ifdef __cplusplus
}
#endif
