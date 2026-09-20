# Native Pi runtime for Sub2API

This is the private execution component of the existing Sub2API product. The account UI's **Native Pi** OAuth option uses the pinned official `@earendil-works/pi-ai@0.85.1` package for login, refresh, and `openai-codex-responses`. Standard accounts retain their existing route.

The admin starts authorization with a Sub2API owner user ID. The runtime owns PKCE and state; the completed credentials carry `harness_kind=pi` and `pi_owner_user_id`. Only API keys owned by that user can use the account. Use a dedicated group to avoid unrelated users selecting this account. Per-account proxies and compact requests are currently rejected on this route.

Requests enter the same `/v1/responses` endpoint. Sub2API obtains the account's token under its existing refresh/cache lock and calls the private runtime. Pi constructs its native headers, including `originator=pi`. Incoming Codex turn metadata and caller-supplied `previous_response_id` are rejected. This route does not relabel an arbitrary Codex request. It accepts Responses input plus function tools, reasoning and output options; it forces `stream=true` and `store=false` upstream. The gateway can still return an ordinary JSON response when the downstream request is nonstreaming.

The session key is an HMAC over the owner, credential record, OAuth account, model and caller session. It is stable across token refresh and isolated across those bindings. A stable caller session header/cache key is required. Concurrent turns in one session return a conflict; serialize them. Pi owns cached WebSocket continuation, selecting delta input with `previous_response_id` only when all other request options and the previous input prefix match. Changing options legitimately causes full-context fallback. `pi_transport` in credentials accepts `auto`, `sse`, `websocket`, or `websocket-cached` (default `sse`).

## Run locally

Use Node 24 or newer. Install with `npm ci --prefix runtime/pi`. Create a private file containing at least 32 random secret characters and set `PI_RUNTIME_SECRET_FILE` in both processes. Start `npm start --prefix runtime/pi`; it binds `127.0.0.1:8091` by default. Set `PI_RUNTIME_URL=http://127.0.0.1:8091` in the gateway. Keep the secret outside the repository.

For Docker, build from the repository root:

```sh
docker build -f runtime/pi/Dockerfile -t local/sub2api-pi-runtime:0.85.1 .
```

Merge `deploy/docker-compose.pi.yml` with the existing Compose deployment. The secret file must be mode 0600 and readable by UID 1000 in both containers. The runtime needs outbound HTTPS/WSS but has no published host port. Browser OAuth runs through the existing admin form; paste the localhost callback URL back into that form. OAuth login sessions expire after ten minutes; only one pending browser login is supported by the SDK's fixed callback listener.

The private runtime API is bearer authenticated:

- `GET /health`: pinned adapter and health.
- `POST /oauth/start`: owner ID; returns authorization URL/session ID.
- `POST /oauth/complete`: matching owner/session and callback URL; returns credentials to the authenticated admin workflow.
- `POST /oauth/refresh`: refresh token plus expected owner/account; rejects a changed account.
- `POST /responses`: bound account credential and Responses input; returns raw upstream SSE, or SSE frames representing native WebSocket events.

Do not publish these endpoints directly. The gateway does not follow redirects or use ambient HTTP proxies when communicating with this private service.

## Evidence and tests

`npm test --prefix runtime/pi` verifies native SDK request formation, raw SSE bytes, real local WebSocket reuse/delta behavior, OAuth state/owner checks, credential isolation, and concurrent-turn rejection. The Go service tests cover API-key ownership, invalid ingress, native refresh routing and refresh-binding validation. The frontend composable test checks that both OAuth steps preserve the same owner and runtime.

`PI_AUTH_FILE=/private/path/auth.json node runtime/pi/verify-live.mjs` opts into two real requests using an existing local OAuth access token. This tests request execution; it does **not** prove a new browser OAuth login. It requests `gpt-6-astra` by default, exercises a function call and result continuation, and independently checks the models declared in upstream response events. Use `PI_TRANSPORT=websocket-cached` to test connection reuse and delta continuation. Tokens, prompts, responses, state values and raw identifiers are never written by this runner.

The passive observer requires complete SSE frames and exact terminal event types. `[DONE]`, EOF, comments and incomplete frames cannot become success. It records terminal status and interruption independently; an interrupted stream with no terminal serializes status as `null`. Duplicate terminal events are idempotent and conflicting evidence remains a conflict. Its buffers and model set are bounded.

`responses_upstream_audit` records ordinary gateway HTTP boundary evidence; `pi_upstream_audit` records the Pi SDK's actual final outbound evidence. Header and body turn metadata are inspected independently. Logs contain field presence, known identifier names, model declarations and turn-state presence/length, never credentials or original identifier/state values. These new audit fields are structured server logs, not a new dashboard screen.

## Live acceptance on 2026-09-20

Native Pi SSE and WebSocket both returned complete responses and passed the function-call/tool-result exercise using the existing local OAuth access token. Both requested `gpt-6-astra`; the observed response model was `gpt-5.6-luna`. The runner correctly failed model acceptance. Do not treat HTTP 200, `originator=pi`, or a completed stream as proof of GPT-6 access. A fresh browser authorization and long-duration refresh still need live acceptance.

The live cached-WebSocket follow-up did send `previous_response_id` and delta input (`connectionsReused=1`, `deltaRequests=1`), but its second response was interrupted with no complete terminal. This is **not** a passing delta-continuation acceptance. SSE is the product default until that live provider path passes. Local WebSocket fixtures pass reuse, delta and isolation. The runtime snapshots caller input so later array mutations cannot corrupt Pi's cached request baseline.

Pi's SSE parser deliberately cancels its reader after the first terminal event. If EOF was not observed, the passive audit records `stream_interrupted=true` even when `terminal_status=completed`; this must not be rewritten as a fully observed transport. The native live runner checks semantic completion/tool behavior separately from this transport flag. The standard gateway runner continues to require a non-interrupted stream.
