# csh-attest

Read-only firmware attestation APM for libcsp / CSP satellite missions.

`csh-attest` is a [csh](https://github.com/spaceinventor/csh) plugin (APM)
that introspects the running system and emits a JCS-canonical
([RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)) JSON manifest
describing every load-bearing piece of state — kernel build-id, kernel
uname, loaded modules, an `/etc` allowlist Merkle root. Manifests can be
signed (Ed25519, [libsodium](https://libsodium.gitbook.io/)), verified, and
diffed. The intended use is **FlatSat ↔ bird parity attestation** — proving
the ground replica matches the on-orbit asset before an uplink, with a
deterministic byte-comparable artifact you can commit to a mission repo.

`v0.3.0` ships four data fields (`etc.merkle`, `kernel.build_id`,
`kernel.uname`, `modules.list`) plus the `schema_version` envelope,
`attest --remote <node>` for fetching a signed manifest from a remote
bird over libcsp, and env-var-overridable port/timeout knobs (see
[Runtime knobs](#runtime-knobs) below). See [SCHEMA.md](./SCHEMA.md)
for the breaking-change policy and [CHANGELOG.md](./CHANGELOG.md) for
release history.

License: Apache-2.0.

## 60-second quickstart

```bash
# 1. Build the APM. Needs meson, ninja, libsodium-dev, libcmocka-dev.
#    On first run meson fetches the libcsp + libapm_csh subprojects.
meson setup build && meson compile -C build

# 2. Boot csh with the APM auto-loaded.
csh -i init/attest.csh

# 3. Inside csh — emit, sign, verify, diff, fetch from a remote bird.
csh> attest --emit                                  > flatsat.json
csh> attest --sign keys/mission.sec                 > flatsat.signed.json
csh> attest --verify keys/mission.pub flatsat.signed.json
csh> attest --remote 0                              > bird.json   # self-loop demo
csh> attest-diff flatsat.json bird.json
```

(`attest --remote 0` exercises the full CSP transport against the loopback
interface inside the same csh process — it's the demo path that proves the
plumbing on a single host. A real FlatSat ↔ bird call uses the bird's CSP
node id and requires routing configured between the two hosts; see the
`attest --remote <node>` section below.)

> Prebuilt `.so` artifacts for Linux x86_64 / arm64 / armv7 are planned for
> tagged releases via GitHub Releases. Until then, build from source — every
> libcsp operator already has the cross-toolchain they need for libcsp itself.

## Commands

### `attest --emit`

Walks the introspection table and writes a JCS-canonical manifest to stdout.
Re-running on the same host produces byte-identical output (deterministic by
construction; non-stable state — timestamps, ASLR, log files — is excluded).

### `attest --sign <secret-key-file>`

Same as `--emit`, then computes an Ed25519 signature over the canonical
bytes and wraps both into a canonical envelope:

```json
{"manifest":"<inner-canonical-as-string>","sig":"<128-hex>"}
```

The secret-key file must be exactly 64 raw bytes (libsodium combined
seed+public format) and `0o600` or stricter — world- or group-readable
keys are refused with `E202`.

### `attest --verify <pubkey-file> <signed.json>`

Parses the envelope, extracts the inner canonical bytes from the
`manifest` field, and verifies the Ed25519 signature against the supplied
public key. Silent on success. Exit `0` = signature valid; exit `1` =
signature invalid (tampered manifest or wrong key); exit `2` = file/format
error.

### `attest-diff <lhs.json> <rhs.json> [--json] [--no-color]`

Field-by-field structural diff over two canonical manifests. ANSI-colored
TTY output by default; `--json` emits a canonical JSON drift report
suitable for piping into runbook automation. Exit codes: `0` = parity,
`1` = drift, `2` = parse / load error.

```
$ attest-diff flatsat.json bird.json
✓ etc.merkle              (match: 3e9d…)
✓ kernel.build_id         (match: 5c4e1ab…)
✗ modules.list            (FlatSat has 47, bird has 46)
   - missing on bird:     ir_camera_driver v2.3.1
✓ kernel.uname            (match)
✗ schema_version          (drift: 0.1.0 vs 0.1.1)
DRIFT: 2 of 5 fields divergent. Exit code: 1.
```

### `attest --remote <node>`

Fetches a manifest from a remote bird over libcsp. The bird's csh-attest
APM listens on the port returned by `attest_csp_port()` (default `100`,
overridable via `ATTEST_CSP_PORT` — see [Runtime knobs](#runtime-knobs));
ground side connects on the same port, the bird walks its introspection
table, and the canonical manifest streams back length-prefixed.
Single-pass operation for now — pass-boundary resume via libdtp is
deferred.

## Runtime knobs

The bird and the ground side both honour two environment variables. They
are read on each server bind / client connect (no caching, no restart
needed for tests; production typically sets them once in the systemd
unit or csh launch wrapper). Out-of-range or unparseable values fall
back to the compile-time default with a one-line stderr warning so
misconfig is visible.

| Var                      | Default | Range       | Effect                                    |
|--------------------------|---------|-------------|-------------------------------------------|
| `ATTEST_CSP_PORT`        | `100`   | `1..127`    | CSP port for `attest --remote` bind/connect |
| `ATTEST_CSP_TIMEOUT_MS`  | `5000`  | `100..60000`| Per-packet read timeout on the ground side  |

The bird and the ground process must agree on the port — mismatched
overrides silently fail to connect (`E101`). `ATTEST_CSP_MAGIC` (the
trigger byte) and `ATTEST_CSP_MAX_PAYLOAD` (linked to libcsp's
`buffer_size` build option) are intentionally **not** overridable; they
are protocol- and build-time constants, not configuration.

## CI integration

The exit-code contract makes the tool drop-in for shell-driven gates:

```bash
# Block a merge if FlatSat drifts from a sealed expected manifest.
# $BIRD is the CSP node id of the target bird (an integer 0..16383).
csh -c "attest-diff expected.json <(attest --remote $BIRD)" \
    || exit 1
```

## Layout

```
src/
  attest.{h,c}        engine + walker + field table
  csh_attest.{h,c}    APM ABI + slash commands + verify/diff drivers
  jcs.{h,c}           JCS canonical emitter (RFC 8785 subset)
  jcs_parse.{h,c}     strict JCS-canonical parser
  diff.{h,c}          structural diff
  diff_render.{h,c}   text + JSON drift renderer
  sign.{h,c}          Ed25519 sign / verify (libsodium wrapper)
  adapters/           one .c per manifest field
tests/                 cmocka unit + integration suites
init/attest.csh        boot script for `csh -i`
vendor/slash/          vendored slash compat header (no subproject)
```

## Targets

Production targets are Linux ≥5.15 on Space Inventor / GomSpace flight OBCs
(arm64+NEON, x86_64). FreeRTOS and bare-metal targets are deferred.

macOS is a "compile-check only" dev target — the slash command surface
disables itself but the `.so` builds, the unit tests run, and the
introspection adapters fall back to deterministic placeholders. Linux CI
is the source of truth.

## Contributing

This is early-stage software. The schema is `v0.1.x` (additive minor bumps
only); a `v1.0` freeze waits on ≥3 ecosystem reviewers signing off. See
[SCHEMA.md](./SCHEMA.md) for the policy. Open an issue before sending a PR
for anything that touches the manifest shape or canonicalization.
