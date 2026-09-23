# J series implementation and acceptance

Source of requirements: the complete user-supplied export
`/Users/zero2fy/Downloads/ChatGPT-分支 · 查看JEV模型文档-20260923-0057.md`
(20,319 lines). Final user clarification at lines 19141–19150 supersedes T07:
vm2api supplies design references only. Supported execution paths remain CPA and
Pi; no vm2api dependency, binary, service, or third backend is to be introduced.

Baseline: `96bfe6093`; Acer initially runs `0.2.7-pi.9-jev-audit`.
This is an implementation ledger, not a declaration of production completion.

## Implemented in this candidate

- Remove Jev keep/drop context pruning and its client control. Preserve native compaction.
- Remove J product selection as a mandatory Jev Safety requirement. Persist a separate
  administrator Safety switch; test all four product/Safety combinations.
- Retire per-user audit bypass. Retain historical markers as historical data only.
- Parse SSE frames and exact terminal events; preserve partial, cancelled, failed,
  oversized and repeated-text evidence. Finalize before Gin context reuse.
- Persist captured/observed bytes, truncation and terminal coverage. Show partial
  coverage in event list/details, never as a full-output pass.
- Keep trace terminal outcomes, count dropped events, show newest historical client
  tool results and label sampling. This is not a J execution engine.
- Label upstream bio refusals separately from local confirmed violations. Migrate
  historical provider-feedback rows without fabricating a 100% classifier score.
- Scope repeated-prompt suppression by user, provider, policy code/version and model.
  The existing Redis first/repeat TTL logic was already implemented and remains.
- Administrator policy review can confirm or release the matching local bio cache;
  preserve original evidence, reviewer, rationale and time. Other hard rules remain.
- Retire model-only automatic permanent account disabling; retain request blocking,
  evidence, counts and manual-review threshold notifications.
- Run migration/persistence/review tests in a disposable PostgreSQL container;
  include those tests and race checks in branch CI.

## Still required before complete release

- T03/T04: validate execution contract, account binding, refresh ownership, isolated
  sessions, per-account capacity and cancellation under actual concurrent requests.
- T05/T06: current CPA/Pi real account import, refresh, continuation and failure tests.
  Cached token or mock success is insufficient evidence of fresh OAuth/refresh.
- T08/T09: shared authorized local Tool Bridge; generic bounded J task router,
  dependent Jev tool steps, selected base-model phases, bidirectional handoff and
  one natural final response. The existing `gpt-6j` Astra alias does not satisfy this.
- T10: persisted key-level J enable, authorized base-to-J model catalog and consistent
  ordinary/single-model/Codex views after the real runtime exists.
- T11: real child-call accounting, idempotency, attribution and durable execution evidence.
- Safety: policy catalog/B0–B4 structured judgments; strict high-risk output gate,
  server-owned pseudonymous safety identifier where supported, scoped/time-limited
  verified research profile, and measured false-positive regression acceptance.
- T12: integrated candidate deployment, frontend/runtime parity, real tool loop,
  two distinct base models, concurrent users, cancellation and rollback evidence.

Never reintroduce the retired 292/312 collector or describe model-list entries,
HTTP 200, imports or container health as end-to-end acceptance.

## Validation on 2026-09-23

- Backend build and frontend production build pass.
- Full securityaudit tests with race checking and disposable PostgreSQL pass.
- SSE capture/terminal regression tests with race checking pass.
- 70 frontend tests pass, including review buttons, partial coverage, key UI,
  user edit and legacy risk-control view.
- Pi runtime's 11 local protocol/isolation tests pass; no claim of fresh OAuth.
- Full handler/service suite still fails. Four representative failures were also
  reproduced against untouched baseline `96bfe6093` in a separate worktree:
  account creation rejects direct credentials, scheduler rejects unbound accounts,
  model-owner test expects OpenAI ownership for the Pegasus alias, and a WebSocket
  moderation fixture attempts an external endpoint forbidden by deployment policy.
  These baseline incompatibilities remain visible; do not weaken production
  account validation merely to make legacy direct-backend fixtures pass.
- No candidate has been deployed. Do not report the production service as updated.
