# Security policy

## What's in scope

csh-attest produces and verifies cryptographic attestations of firmware
state. The integrity-critical surface is:

- **Signing** (`attest --sign`, `sign.c`): Ed25519 signature generation,
  secret-key loading, key-permission gate (`E202`).
- **Verification** (`attest --verify`, `attest_verify_run`): envelope parse,
  signature check, public-key handling.
- **JCS canonicalization** (`jcs.c`, `jcs_parse.c`): RFC 8785 emitter and
  strict parser. Drift between the two = silent signature failure or, worse,
  a tampered manifest that round-trips byte-identically.
- **CSP transport** (`csp_client.c`, `csp_server.c`, `csp_protocol.h`):
  the `attest --remote` request/response framing.

Anything that could be used to forge a valid signature, accept a tampered
manifest as parity, or smuggle bytes through canonicalization without
detection is in scope.

## What's out of scope

- Bugs in `spaceinventor/csh`, `spaceinventor/libcsp`, `libsodium`,
  `libcmocka`, or any other dependency. Report those upstream.
- Key generation (we don't do it; we only consume libsodium-format keys).
- Filesystem permissions outside the secret-key file (`E202`).
- Denial of service against the `attest --remote` listener (the bird is
  trusted and the protocol is single-shot).

## How to report

Email the maintainer (see `git log --format='%ae' src/sign.c | head -1`)
with the subject prefix `[csh-attest security]`. Include:

- Affected version(s) and commit SHA.
- Reproduction steps or PoC.
- Your assessment of severity.

We will acknowledge within 5 business days. Coordinated disclosure window
is 90 days from first contact unless we agree otherwise.

**Do not open a public issue or PR for in-scope vulnerabilities.** A public
fix commit gives an attacker a roadmap; we'd rather coordinate the
disclosure with anyone running the affected version on a real bird.

## Hardening notes for operators

- Keep secret-key files at `0o600` or stricter. csh-attest enforces this
  at sign time (`E202`); pre-commit hooks should enforce it at rest.
- Pin the version (`v0.x.y`) in your Yocto recipe / Dockerfile / package
  manifest. Don't track `main`.
- Verify the `.so` you ship matches a tagged release commit. The CI artifact
  hash is recorded in each GitHub Actions run.
- The `attest --remote` listener binds an unauthenticated CSP socket — anyone
  on the same CSP fabric who can route to the bird's `ATTEST_CSP_PORT` can
  pull the manifest. The manifest is read-only and signed; treat it as
  intentionally public.
