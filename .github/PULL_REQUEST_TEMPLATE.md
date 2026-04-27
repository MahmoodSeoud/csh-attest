## Summary

<!-- 1-3 bullets on what changes and why. Lead with the user-visible effect. -->

## Test plan

- [ ] `meson test -C build --print-errorlogs` passes locally
- [ ] CI green on Ubuntu x86_64 + arm64 + Alpine x86_64
- [ ] If this changes a manifest field, JCS canonicalization, or the signed
      envelope: there is a linked issue and the schema policy in `SCHEMA.md`
      has been re-read
- [ ] If this renames or removes an exported symbol: VERSION bumped and
      CHANGELOG has a Migration note

## CHANGELOG

<!--
Drop the entry under [Unreleased] (or under the next version heading if a
release is in flight). Reference: existing entries in CHANGELOG.md follow
Keep a Changelog with Added / Changed / Fixed / Notes / Out of scope.
Lead each bullet with the user-visible effect; the why goes inline.
-->

## Notes for reviewer

<!-- Anything non-obvious: surprising libcsp behavior, why the test stub
needs the weak attribute, why this is the smallest fix. Optional. -->
