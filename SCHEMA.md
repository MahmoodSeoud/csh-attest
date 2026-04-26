# csh-attest manifest schema

The csh-attest manifest is the moat. Once a mission commits to a
manifest format, every CI pipeline, runbook, audit log, and post-mortem
that consumes it acquires a switching cost. This document is the binding
description of that format and the policy that governs its evolution.

Schema version: **`0.1.0`**.

## Canonicalization

All manifests emitted by csh-attest are JCS-canonical JSON
([RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785), strict subset):

- Object keys sorted by UTF-8 byte order (UTF-16 sort upgrade deferred —
  v1 schema fields are ASCII).
- Array element order preserved verbatim (RFC 8785 §3.2.3).
- No whitespace anywhere in the output.
- Strings escape per §3.2.2.2; control bytes via `\u00XX`; UTF-8 ≥ 0x80
  passes through unchanged.
- Unsigned integers in decimal, no leading zero, no sign, no exponent.

Re-running `attest --emit` on the same host produces byte-identical
output. Cross-implementation compatibility is asserted against the
[cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization)
reference vectors (vendored in `tests/jcs/vectors/`).

## Stable fields (v0.1.x)

| Key               | Type   | Determinism | Source                                        |
|-------------------|--------|-------------|-----------------------------------------------|
| `etc.merkle`      | string | `STABLE`    | SHA-256 root over allowlist of `/etc` paths   |
| `kernel.build_id` | string | `STABLE`    | GNU build-id ELF note from `/sys/kernel/notes`|
| `kernel.uname`    | object | `STABLE`    | POSIX `uname()` (machine, release, sysname, version) |
| `modules.list`    | array  | `STABLE`    | `/proc/modules` + `/sys/module/<m>/srcversion`|
| `schema_version`  | string | `STABLE`    | Manifest schema version (this document)       |

Field order in the canonical output is byte-sorted: `etc.merkle`,
`kernel.build_id`, `kernel.uname`, `modules.list`, `schema_version`.

Per-field size budgets (design doc 1F): `etc.merkle` 32 B (root only),
`kernel.build_id` 64 B, `kernel.uname` 256 B, `modules.list` 8 KB,
`schema_version` 16 B. Raw envelope budget ≤32 KB; hard cap 200 KB.

## Signed envelope

`attest --sign <key>` wraps the canonical manifest in a canonical
two-field outer envelope:

```json
{"manifest":"<inner-canonical-as-string>","sig":"<128-lowercase-hex>"}
```

- `manifest` is the inner canonical bytes embedded as a JSON string —
  per RFC 8785 §3.2.2.2 escape rules. A downstream parser unescapes back
  to the bytes the signature was computed over.
- `sig` is an Ed25519 detached signature
  ([libsodium `crypto_sign_detached`](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures)),
  64 bytes, lower-case hex.
- The signature is computed over the **inner canonical bytes**, never
  over the outer envelope and never over compressed bytes (sign before
  compress, OCI / cosign convention).

`attest --verify <pubkey> <signed.json>` reverses the operation: parse
envelope → extract `manifest` → hex-decode `sig` → verify against the
supplied 32-byte Ed25519 public key.

## Breaking-change policy

The schema follows semver with explicit per-class commitments.

### Major bump (v0.x → v1.0, future v1.0 → v2.0)

- Allowed only when one of: a stable field is renamed; a stable field
  changes type; the canonicalization scheme changes; the signature
  envelope shape changes.
- A migration tool **must ship before the major bump** that converts
  one version's manifests into the next forward and (where lossless)
  back. Without the migration tool the bump does not happen.
- v0.x → v1.0 is gated on **≥3 ecosystem reviewers** signing off
  (per design doc Open Question #2 — the founder retains BDFL on v0.x;
  v1.0 freeze is consensus-driven).

### Minor bump (v0.1.x → v0.2.0, etc.)

- Additive only. New fields may be added; no existing field may be
  renamed, removed, or have its type or determinism class changed.
- Old verifiers continue to verify new manifests against fields they
  recognize; unknown keys are surfaced by `attest-diff` as `LHS_ONLY` or
  `RHS_ONLY` records with no exit-code escalation.

### Patch bump (v0.1.0 → v0.1.1, etc.)

- No schema changes. Bug fixes and documentation corrections only.

## Determinism contract

- `STABLE` — same bytes across runs and reboots on the same host.
- `RACY` — may vary mid-run but is captured via a single sysfs/proc
  snapshot (current example: `modules.list` if a module hot-loads during
  the walk).
- `VOLATILE` — explicitly excluded from the canonical hash. Reserved for
  fields like `attest_time_utc` (not emitted in v0.1.x) where the value
  is informational only.

`v0.1.x` ships only `STABLE` fields. Adding a `VOLATILE` field is a
minor bump and the canonical-hash subset shrinks accordingly.

## What this schema does not promise

- It does not promise that two **different hosts** running the same
  software produce identical manifests. `etc.merkle` includes hostnames,
  `kernel.build_id` includes per-build entropy. Cross-host byte
  comparison is the **point** of the tool — drift is signal, not noise.
- It does not promise reproducibility of the **build** that produced
  `csh-attest` itself. That is a separate property of the Yocto layer
  (design doc 1G).
- It does not extend to FreeRTOS / bare-metal targets. Those are v1.1+.
