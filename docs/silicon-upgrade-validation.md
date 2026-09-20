# Silicon v0.2.7 integration status — 2026-09-20

This is an integration candidate, not a production release. Do not replace the
running Silicon image based only on the successful checks below.

## Scope and source provenance

- Base: `silicon/v0.2.7-jev-hardening-20260920`, including the Jev adapter,
  GPT-6J request controls, and bounded plan-aware Codex state harvesting.
- Preserve the Silicon deployment's CPA account boundary, account import and
  quota bridge, balance grants, audit history/adaptive review, and related UI.
- The production customization overlay came from a source directory snapshot.
  Some source files were modified after the currently running image was built;
  exact source-to-running-image equivalence has not been established.
- CPA, production PostgreSQL, Redis, and running application containers were
  not changed during these checks. Pi customization branches are excluded.

## Corrections made during integration

- Keep native TypeSafe routing separate from CPA audit routing. GPT-6J requires
  blocking Jev, retains the full received context for classification, and does
  not honor the legacy audit bypass or runtime-envelope cleaning shortcuts.
- Persist conversation revocations in PostgreSQL through migration
  `239_security_audit_revocations.sql`. Redis eviction or process replacement
  must not reopen a revoked conversation. Storage lookup failures reject
  continuation temporarily rather than reporting an unrevoked session.
- Preserve Jev's protocol and credential editor when editing an existing node.
  Changing providers clears the credential and disables the draft node; switching
  to the CPA provider uses the deployment's CPA origin.
- Avoid loading account relations on metadata-only bulk updates. Credential and
  proxy changes still validate the mandatory CPA destination, and runtime
  scheduling continues to reject incompatible accounts.
- Require actual `Block` responses for the harmful live Jev fixtures, rather
  than accepting any non-`Allow` response as a successful block.

## Verified checks

| Check | Result and limit |
| --- | --- |
| Embedded backend build | Passed on the Linux validation host |
| Backend static analysis | `golangci-lint`: 0 issues, including the final persistence test additions |
| Frontend typecheck/build | Passed; bundle-size warnings remain |
| Full frontend regression run | 303 files / 2244 tests passed; two additional Jev editor regression cases were then added and the affected 14-test suite passed |
| Focused backend regression | Security audit, Jev, GPT-6J, Codex state, CPA, and balance-grant selections passed in service, securityaudit, and handler packages |
| Full physical backup and upgrade rehearsal | All 27 encrypted parts passed size/SHA-256 checks; gzip CRC and PostgreSQL 18.6 `pg_verifybackup` passed. Recovery completed with networking disabled. Two migration passes succeeded; core identity/entitlement table counts and content fingerprints and the usage-log count were unchanged |
| PostgreSQL schema rehearsal | Restored the current production schema and all 300 migration records to a disposable database; application migrator succeeded twice, ending with 303 records |
| Revocation persistence | Real PostgreSQL test passed: idempotent writes, reopen with a new connection, unrelated key isolation, and errors on an unavailable connection |
| Service startup smoke | Health, administrator login, embedded homepage, audit config/runtime, account list, and user list returned 200 in isolation; synthetic Redis and a synthetic administrator were used |
| Live Jev enhanced compaction | Passed native classification and protected-context invariants; the sample retained every item, so no compression gain is claimed |
| Live Jev acceptance | `jev-1.13.0`: English/Chinese benign and defensive fixtures returned Allow; English/Chinese credential-theft fixtures returned Block (6/6) |

The Jev credential is supplied only at execution time from the existing local
credential store. It is not present in source, reports, or test output. These
six fixtures establish connectivity and basic behavior, not a general accuracy
or false-positive rate.

## Unresolved release gates

1. The full backend unit suite is **not green**. The preserved CPA-only policy
   conflicts with numerous upstream tests that construct direct OAuth or other
   provider accounts. There are also fixture failures and a service-suite
   timeout. These need an explicit compatibility inventory and resolution;
   the suite has not been disabled or reported as passing.
2. After importing the current local Auth, CPA advertises `gpt-6-astra`, but a
   real Responses request returns `gpt-5.6-luna`. Native generation with the
   advertised upstream `gpt-reserve` also returns Luna. GPT-6J acceptance is
   blocked by this model mismatch. The candidate now checks response model
   evidence in JSON, SSE, and both WebSocket forwarding paths.
3. The production account pool currently contains a CPA API-key bridge. A real
   OAuth/plan-aware state capture and user-distribution acceptance test remains
   outstanding. Token length or envelope shape alone does not establish model
   capability or response quality.
4. Enhanced compaction is an optional pre-pass for explicit HTTP compaction
   requests. It preserves user/system/developer/tool items and recent context,
   and retains the original input on classifier failure. It does not rewrite
   opaque server-side `previous_response_id` state or ordinary WebSocket turns.

## Historical migration provenance

The applied `149_user_balance_grants.sql` record was retained unchanged. Its
original source file was absent both from the copied source tree and from the
running image's embedded migration names. The current
`151_user_balance_grants.sql` was recovered from the running ELF binary and
exactly matches the source file's trimmed SHA-256. Both the schema-only and full
physical-backup rehearsals passed without rewriting migration checksums or
history. This establishes upgrade compatibility; it does not reconstruct the
missing historical migration text.

## Focused reproduction

From `backend`, run:

```sh
go test ./internal/service ./internal/securityaudit ./internal/handler \
  -run 'Test(SecurityAudit|RunSecurityAudit|RequiredJev|Jev|GPT6J|OpenAICodex|CPA|UserBalance)' -count=1
go test ./internal/repository -run 'TestBulkUpdate.*CodexFingerprint' -count=1
```

For the opt-in PostgreSQL persistence test, provide
`SUB2API_REVOCATION_TEST_DSN` pointing to a disposable database whose name ends
in `_rehearsal`, after applying migrations. Run
`go test ./internal/repository -run TestSecurityAuditRevocationPostgresPersistence -v -count=1`.
For live TypeSafe tests, supply `SUB2API_JEV_LIVE_KEY` only to the test process
and run `go test ./internal/securityaudit -run '^TestJevLiveAcceptance$' -v -count=1`.

No production application deployment is included in this candidate; the separately authorized CPA Auth import is recorded below.


## Local Auth and proxy pool verification (2026-09-20)

The user's current local Codex Auth was uploaded to the existing matching CPA
identity. Credential preflight returned 200, exact readback verification passed,
and the previous credential file was backed up privately. No credential material
is included in this repository or these reports.

The local sleep-state pool contains 89 HTTP proxy routes. Its config was staged
privately under `/home/ubuntu/sub2api-deploy/state-pool/config.json` with mode 0600.
Server-side connectivity checks found 70 routes with CONNECT 200 and verified TLS;
19 returned 502. This is configuration staging and transport verification only:
the staged service has not been started and remote state harvesting is pending.

Personal state policy accepts length 292 and rejects 312; Team policy targets 332
and rejects 356. The inspected local runtime had active and standby personal
states of length 292. Length and state shape do not prove generation model identity.

The application candidate has not been deployed. The live CPA Auth import is a
separate user-authorized operation and does not change the running Sub2API image.

A private Sub2API merge fragment was also generated at
`/home/ubuntu/sub2api-deploy/state-pool/sub2api-pool.fragment.yaml` (0600).
Its `gateway.openai_codex_ticket.harvest_proxy_urls` list was read back and
matched all 89 source routes exactly. It is not a complete application config
and has not been merged into the running application configuration.

Final candidate checks after response-model enforcement: focused service,
securityaudit, handler, and repository tests passed; `golangci-lint run ./...`
reported 0 issues; `go build ./cmd/server` succeeded. The explicit state-policy
test includes rejected personal 312 and Team 356 cases. The broader backend
suite remains a release gate as recorded above.
