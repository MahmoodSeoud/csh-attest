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

`v0.4.0` ships four data fields (`etc.merkle`, `kernel.build_id`,
`kernel.uname`, `modules.list`) plus the `schema_version` envelope,
`attest --remote <node>` for fetching a signed manifest from a remote
bird over libcsp, env-var-overridable port/timeout knobs (see
[Runtime knobs](#runtime-knobs) below), and `attest --keygen <prefix>`
for one-shot Ed25519 keypair provisioning. See [SCHEMA.md](./SCHEMA.md)
for the breaking-change policy and [CHANGELOG.md](./CHANGELOG.md) for
release history.

License: Apache-2.0.

## Prerequisites

You need [`spaceinventor/csh`](https://github.com/spaceinventor/csh) installed and on your `PATH`. **This is NOT the Berkeley C shell** — `csh -h` should print a copyright line that mentions `Space Inventor A/S` (csh has no `--version` flag; the help banner carries the version-ish info). If your `csh` is `tcsh` / Berkeley (`/bin/csh` on macOS and many Linux distros), it'll silently swallow `init/attest.csh` and dump you at a useless C-shell prompt. Build spaceinventor/csh from source per its README before continuing.

Build deps for csh-attest itself: `meson` (≥ 1.0), `ninja`, `libsodium`, `libcmocka`.

| Distro | Install |
|--------|---------|
| Ubuntu/Debian | `sudo apt-get install -y meson ninja-build pkg-config libsodium-dev libcmocka-dev` |
| Alpine        | `apk add --no-cache build-base meson ninja pkgconfig libsodium-dev cmocka-dev linux-headers` |
| macOS         | `brew install meson ninja pkg-config libsodium cmocka` (compile-check only — see [Targets](#targets)) |

## 60-second quickstart

```bash
# 1. Build the APM. On first run meson fetches the libcsp + libapm_csh
#    subprojects (Linux only; ~30s extra). macOS skips both.
meson setup build && meson compile -C build

# 2. Boot csh with the APM auto-loaded. The init script first runs
#    `csp init -d 0` to disable libcsp deduplication for the loopback
#    --remote demo (csh's CSP_DEDUP_ALL default drops chunked manifest
#    packets — see init/attest.csh for the full why), then `apm load`s
#    the .so and registers the slash commands.
csh -i init/attest.csh

# 3. Inside csh — generate keys, emit, sign, verify, diff, fetch from
#    a remote bird. --keygen writes <prefix>.pub (mode 0644) and
#    <prefix>.sec (mode 0600 — --sign refuses anything looser).
csh> attest --keygen keys/mission
csh> attest --emit                                  > flatsat.json
csh> attest --sign keys/mission.sec                 > flatsat.signed.json
csh> attest --verify keys/mission.pub flatsat.signed.json
csh> attest --remote 0                              > bird.json   # self-loop demo
csh> attest-diff flatsat.json bird.json
```

**Running non-interactively** (CI gates, scripts, headless boxes): csh's
slash readline needs a real PTY — piping commands in via `echo … | csh`
prints `Failed to init slash` and bails. Wrap with `script -qc`:

```bash
script -qc 'csh -i init/attest.csh "attest --emit"' /dev/null > flatsat.json
```

`csh` does NOT support a `-c "..."` flag; the second positional arg to
`csh -i <init>` is the one-shot command line slash will execute after
the init script.

**Don't have `csh` installed yet?** `meson test -C build` runs the
cmocka suite — coverage spans emit, sign, verify, diff, the libcsp
transport, the runtime knobs, and the `attest --help` text. The exact
test count varies as adapters are added; check `meson test -C build
--list` for the current set. If `meson setup` ends with a yellow
`WARNING: cmocka not found — tests will be SKIPPED`, install
`libcmocka-dev` and re-run `meson setup --reconfigure build` before
running the test target. The tests cover the engine; the live
integration also depends on a struct-shape match with csh's slash ABI
(see `vendor/slash/slash/slash.h`), so a working `attest --help`
against your installed csh is the final sanity check.

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
keys are refused with `E202`. Generate one with `attest --keygen` (below).

### `attest --keygen <prefix>`

Generates a fresh Ed25519 keypair via libsodium and writes
`<prefix>.pub` (32 bytes, mode `0644`) and `<prefix>.sec` (64 bytes,
mode `0600`). Refuses to overwrite an existing file (`O_EXCL`) — to
rotate a mission key, delete or rename the old pair first. Operators
who manage keys with external tooling (sodium-cli, an HSM) can skip
this and provide their own files in the same on-disk format.

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

### `attest --help` / `-h`

Prints the inline usage block — subcommand list, the two env-var knobs
(`ATTEST_CSP_PORT`, `ATTEST_CSP_TIMEOUT_MS`), and the design-doc 0/1/2/3
exit-code contract. Exit `0`. The text is the same one csh's `help attest`
shows; `--help` exists so Unix muscle memory works when csh is invoked
non-interactively (`script -qc 'csh -i init/attest.csh "attest --help"'`)
without dropping into an interactive shell.

## Runtime knobs

The bird and the ground side both honour two environment variables. They
are read on each server bind / client connect (no caching, no restart
needed for tests; production typically sets them once in the systemd
unit or csh launch wrapper). Out-of-range or unparseable values fall
back to the compile-time default with a one-line stderr warning so
misconfig is visible.

| Var                      | Default | Range       | Effect                                    |
|--------------------------|---------|-------------|-------------------------------------------|
| `ATTEST_CSP_PORT`        | `13`    | `1..16`     | CSP port for `attest --remote` bind/connect |
| `ATTEST_CSP_TIMEOUT_MS`  | `5000`  | `100..60000`| Per-packet read timeout on the ground side  |

The port range mirrors csh's `lib/csp/meson_options.txt`
(`port_max_bind=16`); ports above 16 silently fail `csp_bind` on the
bird side. Default `13` sits above the standard CSP service ports
(0..7) and `PARAM_PORT_SERVER` (10) but inside the bind window.

The bird and the ground process must agree on the port — mismatched
overrides silently fail to connect (`E101`). `ATTEST_CSP_MAGIC` (the
trigger byte) and `ATTEST_CSP_MAX_PAYLOAD` (linked to libcsp's
`buffer_size` build option) are intentionally **not** overridable; they
are protocol- and build-time constants, not configuration.

## Error codes

Every diagnostic is one structured line on stderr (high-frequency ones are
followed by a `cause:` and `fix:` line). Codes are stable; the exit-code
column is the shell return value when the command takes the error path.

| Code | Family            | Meaning                                           | Exit |
|------|-------------------|---------------------------------------------------|------|
| E001 | I/O / parse       | Cannot open / read / parse file as JCS-canonical  | 2    |
| E099 | I/O               | (reserved)                                        | —    |
| E101 | CSP transport     | `csp_connect` to the bird failed                  | 3    |
| E102 | CSP transport     | Read timed out / short read / empty response      | 3    |
| E103 | CSP transport     | Out of CSP buffers (libcsp pool exhausted)        | 3    |
| E104 | CSP transport     | Malformed length-prefix header from the bird      | 3    |
| E105 | I/O               | File exceeds the 1 MB sanity cap                  | 2    |
| E201 | crypto / verify   | Ed25519 signature verification failed             | 1    |
| E202 | crypto / keys     | Secret-key file is world- or group-readable       | 2    |
| E203 | crypto / keys     | Cannot load public/private key (malformed/short)  | 2    |
| E204 | crypto / output   | Out of memory while building the signed envelope  | 3    |
| E205 | crypto / runtime  | libsodium init or signing failure                 | 3    |
| E901 | programmer error  | Unknown flag, OOM, or short write                 | 2-3  |

CI gates can dispatch on the exit code alone (the message is for humans):

```bash
script -qc 'csh -i init/attest.csh "attest --verify keys/mission.pub flatsat.signed.json"' /dev/null
case $? in
  0) ;;                                    # signature valid
  1) echo "TAMPER DETECTED" >&2; exit 1 ;; # E201 path
  2) echo "operator error"  >&2; exit 2 ;; # missing file, bad key, parse err
esac
```

`script -qc` allocates a PTY for csh's slash readline (csh exits with
"Failed to init slash" when stdin/stdout aren't a terminal, e.g., in
most CI runners or under shell pipelines). The exit code propagates
through `script` unchanged.

## CI integration

The exit-code contract makes the tool drop-in for shell-driven gates.
csh's positional-arg form runs ONE slash command per invocation, so the
ground-side fetch and the diff are two `script -qc` wrappers piping
through a temp file (csh has no `<(...)` shell process substitution):

```bash
# Block a merge if FlatSat drifts from a sealed expected manifest.
# $BIRD is the CSP node id of the target bird (an integer 0..16383).
bird=$(mktemp)
script -qc "csh -i init/attest.csh 'attest --remote $BIRD'" /dev/null > "$bird"
script -qc "csh -i init/attest.csh 'attest-diff expected.json $bird'" /dev/null
rc=$?
rm -f "$bird"
[ $rc -eq 0 ] || exit 1
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

[CONTRIBUTING.md](./CONTRIBUTING.md) has the full PR checklist; new bugs
go through `.github/ISSUE_TEMPLATE/bug_report.yml` (the version + csh
version + target OS fields cut triage time roughly in half).

## Questions

For usage questions, design discussion, or "is this the right tool for
my mission?" — open a [GitHub issue](https://github.com/MahmoodSeoud/csh-attest/issues/new/choose)
using the **Feature request** template (it has a free-form motivation
field) or comment on an existing one. There is no Discord or mailing
list yet; the volume doesn't warrant one and a public issue thread is
better archived than a chat scrollback.

For **security-sensitive** reports — sig-validation bypasses, key-handling
flaws, anything that touches the integrity contract — see
[SECURITY.md](./SECURITY.md). Do not file those as public issues.

For questions about csh itself, libcsp routing, or the `apm load`
mechanism: those belong upstream at
[spaceinventor/csh](https://github.com/spaceinventor/csh).
