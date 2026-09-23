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

- T03/T04: complete live validation of execution contract, account binding, refresh ownership, isolated
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
- The audit/Pi changes through commit `7c17d5854` were deployed as `0.2.7-pi.10-oauth-recovery`. Generic J collaboration and Tool Bridge remain outside that release.

## Pi shared-account correction

- Keep credential ownership and token refresh binding with the importing owner.
- Authorize each caller using the authenticated key, active user, active
  OpenAI group and the selected account's group membership. Reject foreign groups.
- Include both caller user and API key in the native session namespace; client
  session names cannot merge two callers. Business groups may contain CPA and Pi accounts; caller authorization remains enforced.
- Targeted Go race tests pass. Twelve Pi runtime tests pass, including two
  simultaneous cached-WebSocket sessions using one synthetic credential against
  a local test upstream: cancelling A preserves B and no output crosses callers.
  This is protocol/isolation coverage, not proof of fresh production OAuth.

## Pi OAuth persistence repair (2026-09-23)

Production OAuth completed but the database still enforced migration 234's
CPA-only CHECK. Migration 244 permits only a fully bound Pi OAuth account or
the existing CPA route and makes a live Pi OAuth identity unique. PostgreSQL
regressions reproduce the old failure, apply the new migration twice, and
check malformed bindings, external routes, duplicate identities and proxies.
OAuth completion now retains its owner/state-bound result until persistence
acknowledgement (maximum ten minutes), buffers early callbacks, and exposes
only credential-free recovery errors. Runtime tests include retry after a
successful exchange, acknowledgement ownership, and delayed SDK prompts.
The import UI describes credential ownership separately from shared group use.

Validation: 13 Pi runtime tests, 13 account-import frontend tests, targeted Go
race tests and PostgreSQL migration checks pass; frontend production build
and Linux embedded backend build pass. A fresh production OAuth import still
requires a new authorization, since the old runtime discarded the failed
import's exchanged credential. Deployment and acceptance results follow below.

## Pi parity and scheduler repair (2026-09-23)

The user completed fresh production OAuth; account 46 exists with its own Pi
credential. Its operator-approved settings are now active, schedulable, concurrency
10. Import defaults and the frontend now use those same settings, allow existing
public or exclusive OpenAI groups and permit CPA/Pi in the same business group.
Credential ownership is independent of group access. Pi gets enable/disable and
reauthorization actions beside the standard test, edit and delete controls.

A real gateway request exposed a scheduler projection defect: metadata discarded
Pi identification and tokens, then attempted full credential validation. New
versioned projections carry only the backend identity and the result of full
validation. Selected accounts still require credential hydration and full
validation before forwarding. OAuth tokens remain outside candidate projections.
The Pi test-model picker now reads its credential's actual runtime catalog instead
of advertising the generic list and unsupported image-generation entries.

Production DeepSeek audit timed out at 10 seconds on a harmless synthetic request,
which later passed background review. Its configured timeout is now 30 seconds;
a real synthetic endpoint probe passed in 4.2 seconds. Blocking policy, other
endpoint switches, and hard rules were preserved. This is availability evidence,
not proof of classifier accuracy.
