# Changelog

All notable changes to csh-attest are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely; the
schema's own breaking-change policy lives in [SCHEMA.md](./SCHEMA.md).

## 0.3.1 — 2026-04-27

DX patch release. README + error UX hardening surfaced by an end-to-end
`/devex-review` audit. No code-path or wire-format changes; safe drop-in
upgrade from 0.3.0.

### Added

- `README.md` — `## Prerequisites` section with the explicit
  spaceinventor/csh install pointer (the previous quickstart silently
  failed when `csh` resolved to Berkeley `/bin/csh`, which is the default
  on macOS and most Linux distros) plus per-distro `apt` / `apk` / `brew`
  one-liners for the build deps.
- `README.md` — "Don't have csh installed yet?" pointer to
  `meson test -C build` as the spaceinventor-free smoke-test path.
  Closes the "infinite TTHW" cliff for evaluators who want to confirm
  the build works before installing csh from a separate repo.
- `README.md` — `## Error codes` reference table covering all 13 codes
  by family (E0xx I/O, E1xx CSP transport, E2xx crypto, E9xx programmer
  error) with their shell exit codes. Plus an example `case $?` block
  showing how to dispatch on exit code in CI runbooks.
- `CONTRIBUTING.md`, `SECURITY.md`, `.github/PULL_REQUEST_TEMPLATE.md`,
  `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`.
  First pass at the repo's outside-contributor surface; previously
  empty.

### Changed

- The four highest-frequency error sites (E001 cannot-open, E101
  connect-failed, E202 key-perms, E203 key-load-failed) now print a
  three-line `<code+msg>` / `cause: ...` / `fix: ...` form instead of
  a single line. Stripe-tier error UX. Existing test assertions
  (`strstr(err, "E001")` etc.) keep passing because the code prefix
  is unchanged.
- `libinfo` banner string and `meson.build` package version bumped to
  `0.3.1`.

## 0.3.0 — 2026-04-26

Hardening release. The bird-side server and ground-side client now read
`ATTEST_CSP_PORT` and `ATTEST_CSP_TIMEOUT_MS` from the environment so
ops can retune without rebuilding. The internal APM dispatch path swaps
to upstream `libapm_csh::libmain`, retiring the hand-rolled section
walker that lived in `csh_attest.c` since session 2.

### Added

- `attest_csp_port()` / `attest_csp_timeout_ms()` accessors in
  `src/csp_protocol.{h,c}`. Both call sites — `csp_server.c` (bind) and
  `csp_client.c` (connect, read timeouts) — now go through these instead
  of the compile-time macros. Defaults unchanged (port 100, timeout
  5000ms); `ATTEST_CSP_PORT_DEFAULT` and `ATTEST_CSP_TIMEOUT_MS_DEFAULT`
  are the new macro names. Out-of-range or unparseable values fall back
  to the default with a one-line stderr warning so misconfig is visible.
- Validation ranges: port `1..127` (libcsp's `port_max_bind` cap is 128
  and 0 is the broadcast convention); timeout `100..60000` ms (catches
  the "5 instead of 5000" typo without locking out fast loopback test
  setups).
- `tests/test_csp_knobs.c` — pure-stdlib cmocka coverage for the
  accessors: defaults, valid override, both range boundaries, the
  zero/above-range/garbage/trailing-garbage paths. Runs on macOS too
  (no libcsp dependency), keeping the env-parse logic exercised
  everywhere we test.
- `subprojects/apm_csh.wrap` is now actually linked. The wrap also
  ships a tiny `diff_files` patch that adds an `#ifndef APM_HAVE_PARAM
  #include <vmem/vmem.h>` to upstream `apm.c` so it compiles for us
  without dragging in libparam.
- `vendor/apm_csh_compat/vmem/vmem.h` and `vendor/slash/slash/{slash,
  optparse}.h` carry the minimal forward-decls needed for apm_csh's
  upstream-layout includes (`<slash/slash.h>`, `<slash/optparse.h>`,
  `<vmem/vmem.h>`) to resolve in our config.
- `src/apm_link_stubs.c` — weak no-op `vmem_add` so the .so links under
  meson's default `-Wl,--no-undefined`. Production csh provides the
  real symbol; the runtime guard short-circuits because we have no
  vmem section.

### Changed

- `src/csh_attest.c` lost ~30 lines: `apm_init_version`, `libmain`, the
  weak `slash_list_add` decl, and the slash section walker are now
  provided by upstream `libapm_csh` (linked via `.as_link_whole()`).
  We keep `apm_init` (strong def overrides apm_csh's weak hidden
  forward decl in `<apm/apm.h>`) and `libinfo` (csh convention, not
  in apm_csh).
- macOS dev builds keep a minimal `apm_init_version` + `libmain` shell
  gated `#ifndef __linux__`. macOS isn't a load target — libcsp +
  libapm_csh aren't built there.
- README quickstart documents the env-var knobs and the libapm_csh
  swap.

### CI

- Ubuntu CI now installs meson via `pip` (>= 1.0) instead of apt.
  Ubuntu 22.04's apt meson is 0.61.x; `diff_files` for wrap-git
  subprojects requires meson 0.62+. Without the bump the apm_csh
  patch silently doesn't apply on Ubuntu (it does on Alpine 3.19's
  apk meson, which is already at 1.3.x).

### Notes — known landmines

- Bird and ground must agree on `ATTEST_CSP_PORT`. Mismatched env
  vars across the two processes silently fail to connect (csp_connect
  returns NULL → `E101`).
- `ATTEST_CSP_MAGIC` (0x41) and `ATTEST_CSP_MAX_PAYLOAD` (1900) are
  intentionally **not** env-overridable. The magic is a protocol
  constant; the max payload is wedged to libcsp's `buffer_size`
  tunable in `meson.build`.

### Out of scope

- libdtp `.session.partial` resume for lossy-pass robustness.
- libparam-backed knobs (this release uses plain env vars; the
  libparam path lands when we need named-knob discovery from `csh ps`).
- Hardware bring-up against a real radio.

### Migration from 0.2.0

Soft breaking change for any out-of-tree code that includes
`src/csp_protocol.h` directly. Two macros were renamed to make room for
the runtime accessors:

| Before (0.2.0)            | After (0.3.0+)                              |
|---------------------------|---------------------------------------------|
| `ATTEST_CSP_PORT`         | `ATTEST_CSP_PORT_DEFAULT` (compile default) |
|                           | `attest_csp_port()` (runtime; reads env)    |
| `ATTEST_CSP_TIMEOUT_MS`   | `ATTEST_CSP_TIMEOUT_MS_DEFAULT`             |
|                           | `attest_csp_timeout_ms()` (runtime)         |

Call the accessor functions in new code so end users get the
`ATTEST_CSP_PORT` / `ATTEST_CSP_TIMEOUT_MS` env-var override path. Use
the `*_DEFAULT` macros only for static-init contexts where you genuinely
need a compile-time constant.

## 0.2.0 — 2026-04-26

Adds `attest --remote <node>`: pull a signed manifest from a remote bird
over libcsp without leaving the csh shell. Closes the FlatSat ↔ bird
parity loop the `0.1.0` notes flagged as deferred.

### Added

- `attest --remote <node>` slash command: opens a CSP connection to the
  bird's `csh-attest` server, exchanges a 1-byte trigger, and streams the
  JCS-canonical signed envelope back over a chunked length-prefixed
  framing (`src/csp_client.{h,c}`).
- Bird-side server (`src/csp_server.{h,c}`) auto-starts during APM init
  on Linux, binds CSP port `100`, and emits the canonical envelope
  produced by the existing `--sign` path. No separate daemon required.
- Wire protocol (`src/csp_protocol.h`): 1-byte trigger →
  4-byte big-endian length header → length bytes of payload, chunked at
  CSP's `MAX_PAYLOAD_LEN = 1900`. RDP intentionally **not** used — the
  length prefix is sufficient for the small-manifest, low-loss
  loopback / single-hop case and removes the RDP handshake from the
  cold-start path.
- `tests/test_remote.c`: end-to-end loopback round-trip exercising the
  client/server pair through libcsp's loopback interface (`csp_if_lo`).
- Pinned subprojects: `subprojects/csp.wrap` (libcsp upstream) and
  `subprojects/apm_csh.wrap` (libapm_csh upstream). Both gated `if
  is_linux` — macOS dev hosts continue to compile the non-CSP parts only.
- `meson.build` tunings: `csp:port_max_bind=128` (so `ATTEST_CSP_PORT=100`
  binds without raising the default cap), and the `c_std=gnu11` default
  documented above (libcsp `csp_crc32.c` / `csp_id.c` need the GNU
  `<endian.h>` extensions; inherits to subprojects).
- CI: Alpine x86_64 image now installs `linux-headers` and `git` so the
  libcsp wrap fetches and the POSIX driver compiles.

### Changed

- `src/csh_attest.c`: argument dispatch grows a `--remote` branch; APM
  init starts the CSP server on Linux. The hand-rolled section walker
  is unchanged — the `libapm_csh` libmain swap is queued for the next
  release.
- README quickstart documents `attest --remote 0` as the loopback demo
  and includes a dedicated `attest --remote <node>` section.

### Notes — known landmines

- **TEST_NODE_ID = 0 is load-bearing.** libcsp's `csp_io.c:134` has a
  loopback shortcut that bypasses src-fill; replies need `dst=0` to hit
  it. Don't change `TEST_NODE_ID` in `tests/test_remote.c` without
  re-reading that comment.
- **macOS is dev-only.** The `csp` and `apm_csh` wraps are gated `if
  is_linux`; `attest --remote` is unavailable on macOS hosts. Compile
  parity is preserved for the rest of the surface.
- CI matrix dropped `alpine-arm64` for now (libcsp + musl + qemu
  reproducibility issues). See the comment in
  `.github/workflows/ci.yml`.

### Out of scope

- `libapm_csh` libmain swap (replaces the hand-rolled section walker
  with the upstream lifecycle). Wrap is fetched but not yet linked.
- libparam runtime knobs for port / payload-id / session-dir.
- libdtp `.session.partial` resume for lossy-pass robustness.
- Hardware bring-up against a real radio.

## 0.1.0 — 2026-04-26

First version that ships a useful product. The csh APM, four data fields,
and the full sign / verify / diff command surface land together.

### Added

- csh APM scaffolding (`libcsh_attest.so`) with the upstream-compatible
  `apm_init_version` / `libmain` / `libinfo` ABI handshake. Hand-rolled
  ELF section walker registers slash commands without depending on the
  upstream `libapm_csh` static library.
- JCS canonical emitter ([RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)
  subset): objects, arrays, strings, unsigned integers, lowercase hex
  bytes. Streaming, sortedness-enforcing — adapters emit keys in sorted
  order or the canonicalizer rejects at runtime.
- Strict JCS-canonical parser, round-trip verified against vendored
  cyberphone reference vectors (Apache-2.0): `french.json`,
  `structures.json`, `unicode.json`. UTF-16 vs UTF-8 sort divergence
  documented as a known limitation against `weird.json`.
- `attest --emit` slash command: emits the canonical manifest to stdout.
- `attest --sign <secret-key>` slash command: emits the manifest wrapped
  in an Ed25519-signed envelope `{"manifest":"…","sig":"…"}`. Refuses to
  sign with world- or group-readable secret keys (`E202`).
- `attest --verify <pubkey> <signed.json>` slash command: parses the
  envelope, extracts the inner canonical bytes, verifies the Ed25519
  signature against the supplied public key. Exit `0` valid, `1`
  invalid, `2` error.
- `attest-diff <lhs.json> <rhs.json> [--json] [--no-color]` slash
  command: structural field-by-field diff producing an ANSI-coloured TTY
  report or canonical JSON drift record. Exit `0` parity, `1` drift,
  `2` parse / load error.
- Adapters: `etc.merkle` (SHA-256 root over `/etc` allowlist),
  `kernel.build_id` (GNU build-id ELF note from `/sys/kernel/notes`),
  `kernel.uname` (POSIX `uname()`), `modules.list` (`/proc/modules` +
  `/sys/module/<m>/srcversion`). All adapters degrade to deterministic
  placeholders on non-Linux dev hosts.
- Ed25519 sign / verify wrapper over libsodium with ARMv8 Crypto
  Extensions auto-detect (~10× speedup on Cortex-A53/A55 per design doc
  4A).
- CI matrix: Ubuntu x86_64, Ubuntu arm64, Alpine x86_64. macOS supported
  as a "compile-check only" dev target.
- README, SCHEMA, breaking-change policy, and conventional-commits
  history covering sessions 1–7.

### Notes

- `attest --remote <node>` (libdtp transport over CSP) and `csh-attest`'s
  Yocto recipe are deliberately out of scope for `0.1.0`. They land in
  the next minor with the rest of the FlatSat ↔ bird transport story.
- The schema is `0.1.x` — additive minor bumps only until `1.0.0`. See
  [SCHEMA.md](./SCHEMA.md) for the full policy.
