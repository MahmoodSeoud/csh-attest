# Contributing to csh-attest

Thanks for considering a contribution. csh-attest is early-stage; the bar for
merge is "ships green CI and doesn't break the canonicalization or signing
contracts." Below is what that means in practice.

## Before you start

- **Anything that touches the manifest shape, JCS canonicalization, or the
  signing envelope: open an issue first.** The schema is `v0.1.x` (additive
  minor bumps only) and any change to the on-wire bytes is a breaking change
  even if no code visibly moves. See [SCHEMA.md](./SCHEMA.md) for the policy.
- Adapter additions (new manifest fields), error-message polish, doc work,
  and CI tightening: send a PR directly.
- Bug reports: use the issue template at `.github/ISSUE_TEMPLATE/bug_report.yml`.

## Local setup

See the [Prerequisites](./README.md#prerequisites) section in the README for
build deps. Then:

```bash
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

12 cmocka tests should pass on macOS (compile-check target) and Linux
(production target). All four `attest` commands plus `attest-diff` are
exercised through their public driver functions; the `attest --remote`
loopback path is Linux-only.

## Pull-request checklist

- [ ] Conventional-commit subject line: `feat:`, `fix:`, `refactor:`, `docs:`,
      `test:`, `build:`, `ci:`, `chore:`. Scope optional but encouraged
      (`fix(csp):`, `feat(0.4.0):`).
- [ ] One logical change per commit. We squash-merge but the squashed message
      reads better when the commits are coherent.
- [ ] `meson test -C build` is green locally before pushing.
- [ ] CI is green on Ubuntu x86_64 + arm64 + Alpine x86_64 before merge.
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (or under the next version
      heading if a release is in flight) for any user-visible change.
- [ ] If you touched `csp_protocol.h`, `attest.h`, `sign.h`, `jcs.h`, or
      `jcs_parse.h`: confirm callers in this repo still build and call out any
      ABI shift in the PR body.
- [ ] If you renamed or removed an exported symbol: bump the package minor
      version (`0.x.0 → 0.(x+1).0`) and add a "Migration" subsection to the
      CHANGELOG entry.

## Things we will reject

- Changes that mock out libsodium or libcsp in tests instead of exercising
  the real code path.
- New runtime knobs without env-var validation + tests in
  `tests/test_csp_knobs.c` style (range, default, garbage, boundary).
- Wire-format changes (`ATTEST_CSP_MAGIC`, length-prefix layout, JCS
  canonicalization) without prior issue discussion.
- Anything that introduces a build-time dependency on glibc-only symbols
  without a musl fallback (Alpine CI is in the gating matrix).

## Reporting security issues

See [SECURITY.md](./SECURITY.md). Don't open a public issue for sig-validation
bypasses, key-loading flaws, or anything that affects the integrity contract.
