# Acer Sub2API deployment

The deployment uses an isolated Docker Compose project at
`/home/ubuntu/services/sub2api-acer`, private credentials/configuration, a fresh
Silicon database backup, PostgreSQL 18, Redis, the preserved CPA runtime, and a
new Cloudflare Tunnel for `api-next.pegasusailabs.com`.

## Credential-bound state collection

Apply `cpa-managed-state.patch` to the exact CPA source used for the
`cpa-local:v7.2.158-spark-auth-fix-20260912` image. Build and run the Codex executor
regression tests before replacing the binary in that base image. The source
worktree is preserved on Acer under `cpa-source`.

The collector reads Sub2API's existing `openai_codex_ticket_enabled` setting.
It calls CPA's management API with an explicit auth index and harvest proxy,
checks a completed response plus the 292-byte encoded state envelope, and
publishes an atomic private snapshot. States are isolated by credential and
requested model; no bearer tokens are copied into the snapshot. 312 states are
rejected. Authorization and rate-limit errors suspend probing for that identity
and model until the collector is restarted after the cause is resolved.

CPA reads `SUB2API_CODEX_STATE_FILE` after choosing the actual credential. A
missing/expired state blocks configured models with 503. A stale controller
heartbeat blocks Codex requests rather than silently continuing without the
configured policy. Managed-state deployments use HTTP upstream transport even
for downstream WebSocket requests, because an already-pooled WebSocket handshake
cannot receive refreshed state headers. Other providers are unaffected.

The collector runs as `sub2api-cpa-state.service` in the ubuntu systemd user
manager, with lingering enabled. Its logs contain only status, model names and
hashed identity markers. Private artifacts and the Compose file must remain out
of Git. The source VPS remains unchanged and can serve as the fallback site.

## Validation

- CPA managed-state tests cover correct binding, wrong identity, disabled state,
  unrelated models, expired state, stale heartbeat, future timestamps and 312.
- Codex executor and helper regression selections pass; the patched CPA builds.
- Proxy routes are chained through the user-supplied dedicated VLESS egress;
  no direct route is included in the harvest pool.
- State shape does not establish upstream model identity; Sub2API's GPT-6J
  response guard still independently rejects a returned model mismatch.


## Unified account management

Each distinct Codex identity now has a Sub2API account with its own groups,
limits and usage. The internal provisioning connection is paused and excluded
from paginated account listings. Explicit synchronization preserves existing
business account disablement and group selection. Imported credentials are
synchronized from the import dialog; duplicate files do not increase identity
counts.

Apply `cpa-account-binding.patch` in addition to the managed-state patch. Copy
`cpa-account-binding-test.go.txt` to `sdk/api/handlers/sub2_account_pin_test.go`
before running the CPA pin tests. The scheduler writes the trusted identity
header after removing client/custom overrides. CPA gives it precedence over
session affinity and fails when the identity cannot be selected.

Deploy `state_slots.py` alongside `cpa-state-collector.py`. The collector keeps
one active and one distinct newer standby per credential/model. It preserves a
healthy active, promotes a valid standby within the refresh window or after
expiry, and replenishes the empty standby slot. The admin endpoint exposes only
lengths, expiry, heartbeat and bounded probe events. This controller performs
time-based promotion; it does not implement the local gateway's response-strike
or model-mismatch feedback promotion.
