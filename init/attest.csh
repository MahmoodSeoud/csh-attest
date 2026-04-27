# csh-attest boot script.
#
# Loads the csh-attest APM into csh. Use as:
#   csh -i init/attest.csh
#
# Disables libcsp deduplication first because csh's main starts with
# CSP_DEDUP_ALL (csp_conf.dedup=3), which on the loopback path used by
# `attest --remote 0` flags the bird's chunked manifest packets as
# duplicates and silently drops them — the ground side then times out
# (E102, "got 0 of N bytes"). `csp init -d 0` re-runs csh's CSP config
# command with dedup off; libcsp itself stays initialised, only the
# dedup *policy* changes, and it takes effect on the next packet.
# On a real radio link operators typically want dedup on (CSP_DEDUP_FWD
# or CSP_DEDUP_INCOMING); with --remote against a remote node id the
# manifest packets won't collide with anything in the dedup window.
csp init -d 0

# Loads the csh-attest APM and registers the full command surface:
# `attest --emit | --sign | --verify | --remote` and `attest-diff`.
# Run `help attest` once you're at the csh prompt for the inline usage.
apm load -p ./build
