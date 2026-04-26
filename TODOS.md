# TODOS — space-sync (csh-attest)

## Open

### dipp-apm scaffolding mine as fallback (re-decision point: weeks 4–8 of v1)
- **What:** If C engineering motivation flags between week 4 and week 8 of v1, revisit the decision to greenfield the APM scaffolding (init lifecycle, CSP service binding, command registration). Lifting the equivalent code from `~/projects/DISCOSAT/dipp-apm/` could save 2–4 weeks.
- **Why:** Greenfield is a deliberate choice (per `/plan-eng-review` Step 0, path D), but if the timeline slips this is the first scope cut to consider before harder cuts (deferring the determinism harness, dropping JCS reference vectors, cutting prebuilt artifacts).
- **Context:** Outside-voice plan review (2026-04-26) argued that lifting the dipp-apm boilerplate does not violate path-D greenfield — it's plumbing reuse, not extending satdeploy. User chose greenfield. This TODO is the safety valve, not a commitment to revisit.
- **Pros:** Gives future-self an explicit re-decision point with no current commitment.
- **Cons:** None.
- **Depends on:** Nothing. Trigger condition is internal (motivation / timeline pressure).
- **Source:** `/plan-eng-review` 2026-04-26 cross-model tension #2.
