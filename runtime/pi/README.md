# Native Pi runtime for Sub2API

This is the private execution component of the existing Sub2API product. The account UI's **Native Pi** OAuth option uses the pinned official `@earendil-works/pi-ai@0.85.1` package for login, refresh, and `openai-codex-responses`. Standard accounts retain their existing route.

The admin starts authorization with a Sub2API owner user ID. The runtime owns PKCE and state; the completed credentials carry `harness_kind=pi` and `pi_owner_user_id`. Only API keys owned by that user can use the account. Use a dedicated group to avoid unrelated users selecting this account. Per-account proxies and compact requests are currently rejected on this route.

Requests enter the same `/v1/responses` endpoint. Sub2API obtains the account's token under its existing refresh/cache lock and calls the private runtime. Pi constructs its native headers, including `originator=pi`. Incoming Codex turn metadata and non-null caller-supplied `previous_response_id` are rejected. This route does not relabel an arbitrary Codex request. It accepts Responses input plus function tools, reasoning and output options; it forces `stream=true` and `store=false` upstream. The gateway returns an ordinary JSON Responses object with a JSON content type when the downstream request is nonstreaming.

For a first request, explicit JSON `null` values for `previous_response_id`, `max_output_tokens` and `client_metadata` are treated as omitted fields. Non-null values keep their existing validation rules.

The Pi Codex adapter has no verified mapping for the Responses `max_output_tokens` parameter. Requests that set a non-null value receive HTTP 400 with `unsupported_pi_field:max_output_tokens`; the limit is never silently discarded or presented as enforced. This must be checked before forwarding in the gateway as well as in this runtime.

The session key is an HMAC over the owner, credential record, OAuth account, model and caller session. It is stable across token refresh and isolated across those bindings. A caller may omit `session-id` and `prompt_cache_key` for an independent one-shot Responses request; the gateway creates a fresh session for that call. For multi-turn full-input reuse, send the same stable session header or cache key on every turn. Concurrent turns in one session return a conflict; serialize them. Pi owns cached WebSocket continuation, selecting delta input with `previous_response_id` only when all other request options and the previous input prefix match. Changing options legitimately causes full-context fallback. `pi_transport` in credentials accepts `auto`, `sse`, `websocket`, or `websocket-cached` (default `sse`).

## Run locally

Use Node 24 or newer. Install with `npm ci --prefix runtime/pi`. Create a private file containing at least 32 random secret characters and set `PI_RUNTIME_SECRET_FILE` in both processes. Start `npm start --prefix runtime/pi`; it binds `127.0.0.1:8091` by default. Set `PI_RUNTIME_URL=http://127.0.0.1:8091` in the gateway. Keep the secret outside the repository.

For Docker, build from the repository root:

```sh
docker build -f runtime/pi/Dockerfile -t local/sub2api-pi-runtime:0.85.1 .
```

Merge `deploy/docker-compose.pi.yml` with the existing Compose deployment. The secret file must be mode 0600 and readable by UID 1000 in both containers. The runtime needs outbound HTTPS/WSS but has no published host port. Browser OAuth runs through the existing admin form; paste the localhost callback URL back into that form. OAuth login sessions expire after ten minutes; only one pending browser login is supported by the SDK's fixed callback listener.

The image healthcheck reads the private secret and calls the authenticated loopback `/health` endpoint. Compose waits for `service_healthy` before starting the gateway. This proves that this runtime process is ready to answer local requests; it does not prove that a particular OAuth account or the upstream model is healthy. Invalid, missing, or unreadable secrets and a stopped runtime fail the probe.

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

## Live acceptance on 2026-09-23

Using an existing local OAuth access token, the native Pi SSE path completed two turns with a function call and tool-result continuation. The request and observed response model were both `gpt-6-astra`. Pi cancels the SSE reader after the terminal event, so the passive observer still reports `stream_interrupted=true`; semantic completion and model identity passed, while the transport did not observe EOF.

The same two-turn exercise passed on the cached-WebSocket path with the observed `gpt-6-astra` model. The second turn reused the connection and sent delta input with `previous_response_id` (`connectionsReused=1`, `deltaRequests=1`). This is evidence for this token and execution path, not a fresh browser OAuth login or long-duration refresh test. The runtime snapshots caller input so later array mutations cannot corrupt Pi's cached request baseline.

`@earendil-works/pi-ai` 0.87.0 has the same public Codex adapter/provider type declarations as the pinned 0.85.1, but its implementation changed. The pin remains 0.85.1 until local fixtures and real OAuth refresh, SSE, cached WebSocket continuation, tool results, and requested-versus-returned model checks pass against the candidate version.

Pi's SSE parser deliberately cancels its reader after the first terminal event. If EOF was not observed, the passive audit records `stream_interrupted=true` even when `terminal_status=completed`; this must not be rewritten as a fully observed transport. The native live runner checks semantic completion/tool behavior separately from this transport flag. The standard gateway runner continues to require a non-interrupted stream.
