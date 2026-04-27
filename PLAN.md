<!-- /autoplan restore point: /Users/mahmood/.gstack/projects/MahmoodSeoud-csh-attest/feat-0.5.0-rootfs-attestation-autoplan-restore-20260427-161122.md -->
# csh-attest 0.5.0 — Rootfs attestation

**Branch:** `feat/0.5.0-rootfs-attestation` (off `release/0.4.0`).
**Schema impact:** additive minor bump per `SCHEMA.md` policy. v0.1.x → v0.2.0.
**Status:** plan, pre-implementation. Run `/autoplan` against this file before
writing C.

## Why

v0.3.x and v0.4.0 attest the kernel + a two-path `/etc` allowlist
(`/etc/hostname`, `/etc/os-release`). That misses **everywhere mission code
actually lives** — `/usr/bin`, `/usr/lib`, `/usr/share/<mission>`,
`/opt/<mission>`, `/lib/firmware`. A bad uplink that only swaps a userspace
binary in `/usr/bin/payload-controller` produces an identical csh-attest
manifest today. That's a hole big enough to fly through.

The user-visible failure mode is silent and post-hoc: bird and FlatSat agree
on the manifest, you authorize the uplink, it lands on a bird that wasn't
actually in the state you thought, and you find out from telemetry hours
later. The whole point of the tool is to make this class of incident
impossible to reach.

## What ships in 0.5.0

Three new manifest fields, one new build option, one new runtime config
file, one CHANGELOG entry, one SCHEMA.md bump.

### New manifest fields

| Key                | Type   | Determinism | Source                                                                  |
|--------------------|--------|-------------|-------------------------------------------------------------------------|
| `binaries.list`    | array  | `STABLE`    | For each path in the mission allowlist: `{path, build_id}` from `.note.gnu.build-id` ELF section |
| `files.merkle`     | string | `STABLE`    | SHA-256 Merkle root over the configured non-ELF allowlist (configs, scripts, blobs) |
| `files.allowlist`  | array  | `STABLE`    | The actual list of paths that contributed to `files.merkle`. Self-describing — bird/FlatSat divergence on which paths were hashed shows up as a diff, not silent skew. |

`schema_version` bumps to `"0.2.0"`.

JCS sort order is preserved (lowercase ASCII, byte-wise). New keys land
between `etc.merkle` and `kernel.build_id` (`b`, `f`, `k`, `m`, `s`).

### Why `build_id` for binaries, content hash for files

ELF binaries already carry a 20-byte `NT_GNU_BUILD_ID` note set by the linker
at build time. We **already parse this** in `kernel_build_id.c` for the
running kernel — same algorithm, applied to userspace ELFs. Cost: 24 bytes
read per file regardless of binary size. A 50 MB `/usr/bin` directory is
hundreds of milliseconds, not minutes.

Build-ids are content-derived hashes of compiler/linker inputs. Two binaries
with the same build-id are bit-identical (modulo deliberate collision).
Drop-in replacement attack? Build-id changes. Recompile from same source
with same toolchain on a deterministic build? Build-id matches and that's
the point — the bird shouldn't have been recompiled at all.

Non-ELF content (`/usr/share/<mission>/pipeline/*.yaml`, scripts, firmware
blobs) doesn't have a build-id. Falls back to SHA-256 content hash, same
algorithm as `etc.merkle`. Keeping these in a separate `files.merkle` field
preserves the "binaries are cheap, content hashing isn't" performance
distinction in the manifest schema itself.

### Configuration

Two layers, in priority order (later overrides earlier):

1. **Compile-time defaults** (Tier 1, ships first): meson options
   ```
   meson setup build \
     -Dbinaries_paths=/usr/bin,/usr/lib \
     -Dfiles_paths=/etc/hostname,/etc/os-release
   ```
   Generates `src/config_defaults.h` at configure time. Static, baked into
   the `.so`. Suitable for Yocto layers that build csh-attest per mission.

2. **Runtime config file** (Tier 2, ships second — possibly deferred to
   0.6.0): `/etc/csh-attest/paths.allow`, line-oriented:
   ```
   # binaries — extracted via build-id
   binary /usr/bin/payload-controller
   binary /usr/bin/telemetry-agent
   binary-dir /usr/lib/mission

   # files — content-hashed
   file /etc/mission/pipeline.yaml
   file-dir /usr/share/pipeline
   ```
   When present, **replaces** the compile-time defaults entirely
   (not merged). Path is config — merging silently is a footgun.

`etc.merkle` is unchanged in 0.5.0. The two existing paths
(`/etc/hostname`, `/etc/os-release`) stay hardcoded in `etc_merkle.c` for
back-compat with 0.4.x verifiers. They can be promoted into the new
`files.allowlist` mechanism in 0.6.0.

### Determinism rules

- Allowlist paths are sorted (byte order) before walking. Same paths in
  different config-file order produce identical manifests.
- Directory adapters (`binary-dir`, `file-dir`) walk **non-recursively**
  in v0.5.0 — flat directory only. Recursion is a 0.6.0 conversation
  because symlink semantics, hidden files, and depth limits are their
  own design exercise.
- Missing files (path in allowlist but file not on disk): hash the empty
  string for `files.merkle` (same as current `etc_merkle.c` behavior),
  emit `build_id: ""` for `binaries.list`. Deterministic placeholder,
  visible in diff.
- Non-ELF in `binaries-paths`: emit `build_id: ""`. Adapter does not
  fall back to content hash — that's `files.merkle`'s job. Mixing them
  would mask configuration mistakes.

### CSP transport

No protocol change. The signed envelope shape stays the same. Manifest
size grows (new fields), so `attest --remote`'s chunking already handles
it via the existing `csp_protocol.c` framing. **Verify** the per-field
size budget table in `SCHEMA.md` and confirm the 200 KB hard cap still
holds with realistic allowlists (e.g. 200 binaries × ~80 B JSON each =
16 KB — fine).

## What's NOT in scope for 0.5.0

| Deferred              | Why                                                              | Bumps to |
|-----------------------|------------------------------------------------------------------|----------|
| Recursive dir walking | Symlink + hidden + depth design exercise; non-blocker            | 0.6.0    |
| Glob patterns         | Same; AIDE-style power without AIDE-style determinism guarantees | 0.7.0+   |
| `etc.merkle` migration to `files.merkle` | Back-compat: 0.4.x verifiers see `etc.merkle`. Promotion is a coordinated bump. | 0.6.0 |
| Mission-config tooling (e.g. `attest --paths-check`) | Not required for first ship; document the file format in README and SCHEMA. | 0.6.0 |
| Yocto reference recipe | Out of repo scope. CONTRIBUTING.md gets a paragraph pointing at the mission allowlist mechanism. | n/a |
| Cosign-style transparency log | Way outside v0.x scope.                                | v1.x+    |

## Architecture

### New files

```
src/adapters/
  binaries_list.c   binaries_list.h    # ELF build-id walker
  files_merkle.c   files_merkle.h     # content-hash Merkle (separate
                                      # from etc_merkle.c for now;
                                      # consider merge in 0.6.0)
src/
  config.c          config.h           # allowlist loader: meson defaults
                                       # OR /etc/csh-attest/paths.allow
tests/
  test_binaries_list.c                 # cmocka: build-id extract + sort
  test_files_merkle.c                  # cmocka: hash root over fixture
  test_config.c                        # cmocka: file parser + override
  fixtures/
    sample-elf-with-buildid            # 24-byte minimal ELF for tests
    sample-elf-no-buildid              # ELF without .note.gnu.build-id
    paths.allow.good                   # well-formed config
    paths.allow.malformed              # comments, blank lines, weird whitespace
    paths.allow.bad-keyword            # rejected with clear error
```

### Reused files

- `src/adapters/kernel_build_id.c::kernel_build_id_extract` — pure ELF
  note walker, takes bytes + length. Lift into a shared
  `src/adapters/elf_build_id.c` and have both kernel and binaries call
  it. **Do not duplicate.** This is one of the few good DRY moves;
  refusing it would be cargo-culted "explicit over clever."
- `src/adapters/etc_merkle.c::compute_etc_merkle` — same algorithm.
  Promote to `src/adapters/path_merkle.c` and have both `etc_merkle`
  and `files_merkle` adapters call it.
- `src/attest.c` — add three rows to `attest_fields[]`. Keep alphabetic
  order. Update `attest_fields_count` automatically (sizeof divides).

### Config loader determinism contract

The `config_load()` function returns a struct with two sorted, owned
arrays of paths (binaries + files). Caller guarantees:

1. Sort is byte-order, stable, deterministic.
2. Duplicate paths are deduplicated (last write wins for the
   binary-vs-file tag — but this is already an error worth surfacing).
3. Empty allowlists are valid; the adapter emits `[]` or
   `SHA256("")` respectively.
4. Config file parse errors are loud (exit non-zero from `--emit`,
   not silent fallback to defaults). A typo in `paths.allow` should
   fail closed, not produce a manifest that silently omits half the
   rootfs.

### DX rules of thumb

- Error messages: `<problem>: <cause>: <fix>`. The 0.4.0 PR explicitly
  added this for CSP errors (see `feat(0.3.2)` commit). Match that
  voice.
  - `attest: paths.allow:7: unknown directive "binnary": expected binary, binary-dir, file, file-dir`
  - `attest: /usr/share/pipeline/foo.yaml: file not in allowlist; declared in /etc/csh-attest/paths.allow but missing on disk`
- Help text: `attest --help` already lists subcommands. Add a brief
  paragraph on configuration sources, point at `paths.allow(5)`-style
  prose in README. Don't bury it.
- Migration story for v0.4.x users: zero action required. With no
  `binaries_paths` set at build and no `paths.allow` at runtime,
  `binaries.list` and `files.merkle` emit `[]` and `SHA256("")`
  respectively. Manifest grows three fields, all empty. Existing
  signing/verifying still works. Consumers that diff manifests see
  three new STABLE fields with empty values — they can opt into
  attesting them when they're ready.

## Test plan

| Test                                 | Where                       | What fails without it                          |
|--------------------------------------|-----------------------------|------------------------------------------------|
| build-id extract from minimal ELF    | `test_binaries_list.c`      | binaries.list emits empty for legitimate ELFs  |
| build-id extract from non-ELF        | `test_binaries_list.c`      | adapter aborts on a script in the allowlist    |
| Merkle root over fixture path list   | `test_files_merkle.c`       | files.merkle isn't deterministic               |
| Empty allowlist                      | both                        | empty config produces non-deterministic output |
| Config parser: well-formed           | `test_config.c`             | regression on directives                       |
| Config parser: comments / blank lines| `test_config.c`             | strict parser rejects valid config             |
| Config parser: malformed             | `test_config.c`             | silent fallback to defaults on typo            |
| Config: meson defaults applied       | `test_config.c`             | compile-time path doesn't reach adapters       |
| Config: paths.allow overrides defaults| `test_config.c`            | runtime config silently ignored                |
| End-to-end: emit → sign → verify     | existing harness            | new fields break the signing envelope          |
| End-to-end: emit → diff against self | existing harness            | new fields break attest-diff                   |
| Determinism: re-run produces same bytes | existing harness extension | new fields introduce non-determinism          |

The cmocka suite is the gate. CI runs Ubuntu x86_64 + arm64 + Alpine
x86_64 per CONTRIBUTING.md. macOS compile-check still applies but the
new adapters return empty on non-Linux (no `/usr/bin` semantics) — same
pattern `modules_list.c` already uses.

## Open questions for review

- **Should runtime `paths.allow` ship in 0.5.0 or 0.6.0?** Tier 1
  (compile-time) covers the use case; Tier 2 (runtime) is nicer DX but
  adds a parser and a self-attestation question (does `paths.allow`
  itself get hashed into `files.merkle`?). Lean: ship Tier 1 in 0.5.0,
  Tier 2 in 0.6.0. /autoplan to confirm.
- **Should `etc.merkle` migrate into `files.merkle` immediately?** No —
  back-compat with 0.4.x verifiers wins. Let `files.merkle` exist
  alongside `etc.merkle` for one release. Promote in 0.6.0 with a
  documented migration note.
- **`binaries-dir` semantics on directories with non-ELF entries?**
  Lean: ELF detection by magic bytes (`\x7fELF`). Non-ELF entries
  emit `build_id: ""` with a one-line warning to stderr. /autoplan
  to confirm whether warning-on-stderr is too noisy for satellite
  operator workflows where stderr might land in syslog.
- **Hard cap on allowlist size?** Lean: 1024 entries per kind
  (binaries + files). Beyond that, the operator's allowlist hygiene
  has bigger problems than us refusing to hash everything.

## Cross-mission generality

The user concern was "this only works for our satellite." Counter-evidence
once 0.5.0 ships:

- Mission A (`/usr/bin`-heavy): `-Dbinaries_paths=/usr/bin,/usr/lib`
- Mission B (`/opt`-heavy): `-Dbinaries_paths=/opt/payload/bin -Dfiles_paths=/opt/payload/etc`
- Mission C (firmware-heavy): `-Dfiles_paths=/lib/firmware/<mission>`

Same `.so`, same engine, same JCS guarantees, same signing envelope.
Per-mission Yocto recipe applies the meson options. **The keys are
already per-mission** (since v0.4.0's `--keygen`); the allowlist is
just one more piece of mission config. That's the product.

## Acceptance criteria

- `attest --emit` on a stock Linux box with default config emits the
  three new fields as empty.
- `attest --emit` with `-Dbinaries_paths=/usr/bin` set at build emits
  one `{path, build_id}` object per ELF in `/usr/bin`, sorted by path.
- `attest --emit` re-run produces byte-identical output (the
  determinism contract from `SCHEMA.md`).
- `attest --sign` / `attest --verify` roundtrip on the new manifest.
- `attest-diff` between two manifests with different `binaries.list`
  highlights per-binary changes (path-level granularity, not
  "binaries.list changed").
- `meson test -C build` is green on Linux + macOS compile-check.
- README and SCHEMA.md updated; CHANGELOG entry under
  `## 0.5.0 — <date>` matches the voice of 0.4.0's entry.

---

# /autoplan REVIEW — 2026-04-27

Review pipeline ran with subagent-only voices (Codex CLI unavailable on
this host). Phase 1 (CEO) + Phase 3 (Eng) + Phase 3.5 (DX) ran. Phase 2
(Design) skipped — no UI scope. Test plan artifact saved to
`~/.gstack/projects/MahmoodSeoud-csh-attest/feat-0.5.0-rootfs-attestation-test-plan-20260427-161641.md`.

## Historical context (recovered from prior design doc)

`~/.gstack/projects/space-sync/mahmood-main-design-20260426-112310.md` line 95
already lists `userspace package digests (dpkg/opkg manifest hash)` as a v0.1
manifest field. It was deferred when v0.1.x shipped only kernel + etc.merkle.
**This plan reinvents the rootfs-attestation field with a different mechanism
(build-id walker) without acknowledging the prior decision.** Either the plan
should explain why it diverges from dpkg/opkg manifest hashing (likely answer:
not all Yocto images have a package manager), or it should incorporate package
manager output as one source alongside build-id.

## Cross-phase themes (independent findings, ≥2 phases)

| Theme | Phases | Severity | Concrete fix |
|---|---|---|---|
| Silent-empty defaults are product cowardice | CEO + DX | CRITICAL | Migration default emits a one-line `WARNING: userspace not attested` on stderr unless `ATTEST_USERSPACE=skip` |
| Missing config introspection surface | CEO + DX + Eng | CRITICAL | Ship `attest --paths` in 0.5.0 (prints resolved allowlist). Cheap (~50 LOC), unblocks self-validation |
| Open-questions are missing-design, not taste | CEO + DX + Eng | HIGH | Resolve all four open questions BEFORE writing C: see resolutions below |
| Build-id alone is insufficient | CEO + Eng | HIGH | Dual-hash: emit BOTH `build_id` AND `sha256` per binary (52 B total per entry, fits budget) |

## Single-voice CRITICAL findings (flagged regardless)

1. **Eng — `kernel_build_id_extract` lift is wrong.** It parses pre-extracted
   `.notes` bytes (the format `/sys/kernel/notes` exposes). A userspace ELF on
   disk needs full ELF header + program-header walk + `PT_NOTE` location
   first. **The "24 bytes per file" claim in PLAN.md:47 is wrong.** It's
   3 reads minimum: ehdr (64 B), phdrs, notes. The "shared helper" lift
   only covers the inner note-walker; outer ELF dispatch is new code.
   Also needs ELF32/64 + LE/BE handling (kernel adapter dodges this; userspace
   cross-compile birds do not).

2. **Eng — Field-size budget is breached.** PLAN.md open-question 4 caps
   allowlists at 1024 each. 1024 × 80 B (binaries) + 1024 × 120 B (files)
   = 200 KB exactly, plus existing fields = **over the SCHEMA.md hard cap
   of 200 KB envelope**. Either lower per-kind cap to 512, or add explicit
   error code (E106) for budget overflow.

3. **Eng — `readdir` directory iteration is filesystem-dependent.** Plan never
   says "sort entries before emit". Two birds with same content but different
   inode allocation order produce different `binaries.list`. **`scandir` +
   lexical compare, or `readdir` + `qsort`** — same pattern `modules_list.c:165`
   already uses.

4. **Eng — Symlink semantics undefined.** `/usr/bin/python → python3.11` is
   the canonical case. Bird with `python → python3.11` and FlatSat with
   `python → python3.10` produce different builds, but plan doesn't say
   whether to `lstat()` first or follow. Pick one, document in SCHEMA.md.

5. **CEO — IMA / dm-verity / AIDE prior art unaddressed.** A reviewer at
   GomSpace will ask: "why aren't you signing
   `/sys/kernel/security/ima/ascii_runtime_measurements`?" The plan has no
   answer. Add a "Prior art" section to PLAN.md and SCHEMA.md.

6. **DX — Migration default is product cowardice.** The plan opens with
   "this hole is big enough to fly through" then proposes a migration where
   v0.4.x users upgrade and produce manifests with empty new fields. That's
   worse than not having the fields — it implies due diligence happened.

7. **DX — No `attest --paths` is the central DX miss.** Operator edits config,
   runs `--emit`, eyeballs JSON. Every comparable tool (AIDE
   `--config-check`, Tripwire `twadmin --check-policyfile`, cosign) has a
   config-validation command.

## Open-questions resolved at /autoplan gate

| # | Original question | Final resolution |
|---|---|---|
| 1 | Tier 2 in 0.5.0 vs 0.6.0 | **D2: SHIP IN 0.5.0.** Runtime `/etc/csh-attest/paths.allow` parser + self-attest the file's SHA-256 in `files.merkle` automatically. Closes the prebuilt-.so distribution gap. |
| 2 | `etc.merkle` migration timing | **D3: NEVER MIGRATE.** etc.merkle stays frozen with its 2 paths (legacy field), files.merkle handles new content-hashed paths. Document in SCHEMA.md as "kept for back-compat with v0.4.x verifiers, will not change." Schema stays 100% additive. |
| 3 | Non-ELF in binary-dir warning | **DECIDED:** at emit time, gated behind `ATTEST_VERBOSE=1` env var. Default-quiet, opt-in-loud. Same shape as `ATTEST_CSP_PORT`. |
| 4 | Hard cap on allowlist size | **DECIDED:** 512 per-kind (binaries + files), enforced at config-load time with new error code E106. Fits 200 KB envelope with margin for existing fields + dual-hash overhead. |

## What's NOT in scope (post-gate, locked in)

- Recursive directory walking — 0.6.0 (symlink+depth design exercise)
- Glob patterns — 0.7.0+ (AIDE-without-determinism)
- `etc.merkle` migration — **never** (D3: dual-emit forever, schema stays additive)
- Yocto reference recipe + canonical OBC allowlist — **0.6.0** (D1: defer until one outside mission integrates and validates)
- Cosign-style transparency log — v1.x+
- IMA/dm-verity integration — out of scope for csh-attest's non-enforcing model. Documented in new "Prior art" section.

## Final v0.5.0 scope (gate-approved)

**Manifest fields added:**
- `binaries.list`: array of `{path, build_id, sha256}` per ELF (dual-hash per CEO+Eng)
- `files.merkle`: SHA-256 Merkle root over content-hashed allowlist (leaf format `SHA256(path) || SHA256(content)` matching `etc.merkle`)
- `files.allowlist`: array of paths that contributed to `files.merkle` (self-describing manifest)

**Configuration (both layers ship in 0.5.0):**
- Tier 1: meson option `option('binaries_paths', type: 'array', value: [])` (NOT csv string)
- Tier 1: meson option `option('files_paths', type: 'array', value: [])`
- Tier 2: `/etc/csh-attest/paths.allow` line-oriented parser
- When `paths.allow` is present, it REPLACES Tier 1 defaults (no merging)
- When `paths.allow` is present, **its SHA-256 is automatically included as a fixed slot in files.merkle** (self-attest)
- Per-kind cap: 512 entries; overflow → E106 refuse-to-emit (clean fail-loud)
- Path-traversal reject: paths must start `/`, no `..`, reject `/proc/`, `/sys/`, `/dev/` prefixes

**New CLI:**
- `attest --paths`: print resolved allowlist (Tier 1 defaults + Tier 2 overrides) for self-validation BEFORE signing

**New error codes:**
- E106: allowlist size cap breached (>512 entries)
- E107: per-file size cap breached (>64 MB content hash)
- E301: configured path resolved to nothing on this rootfs (one-line stderr, manifest still emits empty for that entry)

**Migration:**
- v0.4.x → v0.5.0 with no config: `attest --emit` prints one-line stderr WARNING about un-attested userspace, exit code stays 0. Suppress with `ATTEST_USERSPACE=skip`.

**Engine changes:**
- New `src/adapters/elf_walker.c` (parses Ehdr → PT_NOTE → notes; handles ELF32/64 + LE/BE) — NOT a "lift" of `kernel_build_id_extract` (the kernel adapter parses pre-extracted notes; userspace ELF needs full ELF dispatch)
- `src/adapters/binaries_list.c` calls into `elf_walker` per file, falls back to content SHA-256 when build-id absent (catches stripped binaries)
- `src/adapters/files_merkle.c` reuses `compute_etc_merkle` algorithm (promote helper to `src/adapters/path_merkle.c`)
- `src/config.c` loader (Tier 1 + Tier 2 with priority + sort + dedup)
- All directory walks use `scandir` + lexical sort (matches `modules_list.c:165`)

**diff_render.c (D4):**
- `binaries.list`: smart truncation at 20 differing entries with "...and N more (run attest-diff --full to see all)"
- `--full` flag forces all path-level lines

## Decision Audit Trail (locked, post-gate)

| # | Decision | Source | Locked |
|---|----------|--------|--------|
| 1 | Fields-only v0.5.0 (defer Yocto recipe to 0.6.0) | D1 user | ✓ |
| 2 | Ship Tier 2 (runtime config) in 0.5.0 | D2 user | ✓ |
| 3 | etc.merkle stays parallel to files.merkle forever | D3 user | ✓ |
| 4 | attest-diff: smart truncation at 20 + --full flag | D4 user | ✓ |
| 5 | ELF walker is new code, NOT a kernel_build_id_extract lift | Eng auto | ✓ |
| 6 | Dual-hash binaries (build_id + sha256) | CEO+Eng auto | ✓ |
| 7 | qsort all directory walks | Eng auto | ✓ |
| 8 | meson option type: 'array' (not CSV) | DX auto | ✓ |
| 9 | Per-kind allowlist cap 512 + E106 | Eng auto | ✓ |
| 10 | Stderr WARNING on migration when userspace not attested | DX auto | ✓ |
| 11 | Ship attest --paths in 0.5.0 | DX auto | ✓ |
| 12 | Self-attest paths.allow when present | DX auto | ✓ |
| 13 | Prior art section addressing IMA/dm-verity/AIDE/dpkg | CEO auto | ✓ |
| 14 | Path-traversal reject in Tier 2 (.., /proc/, /sys/, /dev/) | Eng auto | ✓ |
| 15 | Per-file 64 MB hash cap + E107 | Eng auto | ✓ |
| 16 | Symlink semantics: lstat() first, hash target string + tag entry | Eng auto | ✓ |
| 17 | TOCTOU: O_NOFOLLOW + fstat + bounded-read or fail-loud | Eng auto | ✓ |

## Decision Audit Trail (auto-decided, by 6 principles)

| # | Phase | Decision | Classification | Principle | Rationale |
|---|-------|----------|----------------|-----------|-----------|
| 1 | CEO | Reframe v0.5.0 as fields-only, defer Yocto recipe | TASTE → SURFACE | (P1, P6) | CEO subagent says recipe IS the product moment; surface at gate so user can override |
| 2 | CEO | Add "Prior art" section addressing IMA/AIDE/Tripwire | MECHANICAL | P1 | Pure addition, no scope expansion, prevents reviewer torpedo |
| 3 | CEO | Reject "etc.merkle silent migration in 0.6.0" | TASTE → SURFACE | P5 | Either subsume now or dual-emit forever — defer is non-additive per SCHEMA.md |
| 4 | CEO | Validate "/usr/bin et al" gap with real OBC layout | MECHANICAL | P3 | One paragraph in PLAN.md, no work expansion |
| 5 | Eng | Replace "shared elf_build_id helper" claim with explicit ELF walker | MECHANICAL | P5 | Plan claim is wrong; correct it now to avoid mid-implementation surprise |
| 6 | Eng | Mandate `qsort` on directory walks | MECHANICAL | P5 | Silent determinism violation; non-negotiable for STABLE field |
| 7 | Eng | Resolve symlink semantics in SCHEMA.md before C | MECHANICAL | P1 | Single-line spec decision, blocks emit determinism |
| 8 | Eng | Dual-hash binaries (build_id + sha256) | TASTE → SURFACE | P1 | Increases per-entry size from 80 B to ~150 B, tightens budget — surface |
| 9 | Eng | Lower per-kind allowlist cap to 512 OR add E106 overflow | TASTE → SURFACE | P5 | Pick one mechanism, surface |
| 10 | Eng | Path-traversal allowlist (reject `..`, `/proc/`, `/sys/`, `/dev/`) | MECHANICAL | P1 | Security floor for Tier 2 |
| 11 | Eng | Per-file 64 MB hash size cap with E107 | MECHANICAL | P5 | Prevents accidental `/var/log` attestation hang |
| 12 | DX | Switch meson option from CSV string to `type: 'array'` | MECHANICAL | P5 | Pure correctness, no scope change |
| 13 | DX | Migration default → one-line stderr WARNING (not silent) | TASTE → SURFACE | P1 | Reasonable people could disagree on stderr-noise tolerance |
| 14 | DX | Ship `attest --paths` in 0.5.0 | TASTE → SURFACE | P1, P2 | Adds ~50 LOC + tests; in blast radius; competitive parity |
| 15 | DX | Self-attest paths.allow when present | MECHANICAL | P1 | Closes the hole the plan was supposed to close |
| 16 | DX | Specify `diff_render.c` summary mode for large arrays | TASTE → SURFACE | P5 | Affects existing renderer; acceptance-criteria spec needed |
| 17 | DX | Add 90-second "attest your mission binaries" README quickstart | MECHANICAL | P1, P3 | Mirrors v0.4.0 quickstart; no architectural change |

## Phase Consensus (subagent-only — Codex unavailable)

```
PHASE        | Subagent verdict           | Critical issues found
─────────────┼────────────────────────────┼──────────────────────
CEO          | Wrong altitude / scope     | 7 (2 critical, 4 high, 1 med)
Design       | SKIPPED — no UI scope      | n/a
Eng          | Architecture flaws + sec   | 11 (4 critical, 5 high, 2 med)
DX           | 6/10 bench, 6 concrete fixes | 6 (2 critical, 3 high, 1 med)
```

