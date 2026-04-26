# Changelog

All notable changes to csh-attest are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely; the
schema's own breaking-change policy lives in [SCHEMA.md](./SCHEMA.md).

## 0.1.0 — unreleased

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
