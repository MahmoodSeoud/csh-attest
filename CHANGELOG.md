# Changelog

All notable changes to csh-attest are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely; the
schema's own breaking-change policy lives in [SCHEMA.md](./SCHEMA.md).

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
