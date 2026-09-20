# Pi integration in Sub2API

This integration belongs to the existing Sub2API account/group/key gateway. The existing Codex session import owns upstream OAuth credentials and token refresh; Pi authenticates with a Sub2API API key through `/v1/responses`.

## Source basis

- Existing source baseline: `49a39b6dc1abed30fd227611e8af1108bc427610` in the user's `sub2api-0.2.6` repository. This is a source snapshot, not an official 0.2.6 release tag.
- Official 0.2.7 comparison: `aea725f2ea644d5592d0bbb1d63b607efa7e200a`. It has not been merged into this worktree. Byte comparisons confirmed `account_codex_import.go`, `openai_oauth_service.go`, and `openai_token_provider.go` match this worktree.
- Pi: `earendil-works/pi` v0.85.1, commit `d981de1229ef899957bbe968bc8dcda02a21f477`; the integration runner uses the published `@earendil-works/pi-ai` package pinned to 0.85.1 with a package lock.

Relevant upstream paths:

- Sub2API `backend/internal/handler/admin/account_codex_import.go`: native session normalization, duplicate identification, preservation of refresh credentials, expiry checks, account/group registration.
- Sub2API `backend/internal/service/openai_oauth_service.go`: refresh and credential update behavior.
- Pi `packages/coding-agent/docs/models.md`: custom provider configuration and literal/environment/command value semantics.
- Pi `packages/ai/src/api/openai-responses.ts` and `openai-responses-shared.ts`: actual request conversion and streaming/tool assembly used by the runner.
- Pi `packages/ai/src/api/openai-codex-responses.ts`: reviewed as the direct Codex provider; its connection-scoped WebSocket continuation is not used by this API-key gateway integration.

The OpenAI key dialog now includes Pi configuration, alongside the existing clients. Merge its `sub2api` provider into `~/.pi/agent/models.json`; retain other providers and keep the file private. The initial model is `gpt-5.5`, which must be enabled for the key's group; edit it to another available model as needed. An existing Codex model selection is reused if available.

## Verification

Install runner dependencies with `npm ci --prefix tools/pi-integration`. Set `SUB2API_KEY_FILE` to a private file containing a Sub2API API key, optionally `SUB2API_BASE_URL` and `SUB2API_MODEL`, then run `npm run verify --prefix tools/pi-integration`.

The runner uses Pi's real adapter, performs two requests with one session ID, validates a function call and its arguments, returns a synthetic tool result, and checks final text and successful stream termination. It disables retries and never logs credentials or raw provider responses. Model acceptance is evaluated separately after both requests, so a model mismatch does not hide the tool-continuation result. A missing or unexpected response-model declaration fails acceptance for every requested model.

Local verification on 2026-09-20:

- Native import updated the matching existing account: 1 updated, 0 created, 0 failed; original groups retained.
- Database booleans confirmed both access and refresh credentials present (no token values exported).
- Pi SDK 0.85.1 returned HTTP 200 twice: first `toolUse`, second `stop`; exact tool-result continuation passed.
- Pi CLI 0.85.1 with the configured provider returned exactly `PI_CLI_OK`.
- Frontend key-dialog and locale tests: 25 passed; TypeScript and production Vite build passed.

Scope: this verifies the existing HTTP Responses path, not Pi WebSocket continuation, all model entitlements, long-duration refresh behavior, or complete feature parity with every proposal in the source discussion. Frontend compilation is separate from updating the running server binary.

## Deployment and GPT-6 acceptance (2026-09-20)

The existing `sub2api` service was updated in place to local build `0.2.6-pi.1`, source commit `aae631525`, image `local/sub2api:pi-aae631525`. Health passed with zero restarts. The served KeysView asset matched the production build and contained the Pi config. Existing PostgreSQL/Redis services, ports, account and groups were retained. No migrations differed from the previous local source reference.

GPT-6 acceptance did **not** pass:

| Path | Requested model | Model declared in response | Result |
| --- | --- | --- | --- |
| Pi SDK -> existing Sub2API | gpt-6 | gpt-5.6-luna | HTTP 200/toolUse, model assertion failed |
| Pi SDK -> existing Sub2API | gpt-6-astra | gpt-5.6-luna | HTTP 200/toolUse, model assertion failed |
| Local auth -> official Codex endpoint directly | gpt-6-astra | gpt-5.6-luna | HTTP 200/response.completed, wrong model family |

Account mappings preserved GPT-6 names, and group model routing was empty. The direct request reproduces the mismatch without Sub2API. This is evidence of the upstream response under this authentication, not proof of its underlying cause or of the model's internal implementation. The runner now defaults to `gpt-6-astra`, observes response-body model declarations, and fails GPT-6 requests unless all observed models belong to the expected family. `SUB2API_EXPECT_MODELS` can explicitly set a comma-separated expectation for other acceptance runs.

Deployment rollback uses the retained image `local/sub2api:before-pi-20260920`. The existing deployment's `docker-compose.override.yml` selects the new image; change its image to the retained one and run `docker compose up -d --no-deps --pull never sub2api` from the existing deployment directory. Database and configuration backups were saved locally before deployment. Do not overwrite the database just to roll back the executable.

## Codex client acceptance and metadata audit

`npm run verify:codex --prefix tools/pi-integration` uses the same private `SUB2API_KEY_FILE`, base URL, and model variables as the Pi runner. It requires Node 24 and an installed Codex CLI supporting `--ignore-user-config` and `--ephemeral`. It names the custom provider `Sub2API`, selects `wire_api = "responses"`, and supplies the gateway key through `env_key`. These are documented [Codex provider settings](https://developers.openai.com/codex/config-reference/).

The runner temporarily relays the real Codex HTTP request through a loopback listener to the existing gateway. Request body bytes and application headers are forwarded unchanged; only HTTP transport headers are handled by the relay. It records field-presence booleans, known metadata key names, HTTP status, terminal event types, and response-model declarations. It never prints keys, prompts, ID values, raw CLI diagnostics, or upstream response text. It runs a fixed no-tools prompt in a temporary directory without changing the user's Codex configuration or auth file. This is an ingress observation, **not a capture of the gateway's outbound request**.

The real Codex CLI run on 2026-09-20 completed with HTTP 200, `response.completed`, and the exact requested final marker. It sent native Responses `input`, `stream=true`, `store=false`, and `x-codex-turn-metadata` containing the keys `installation_id`, `session_id`, `thread_id`, `turn_id`, and `window_id`. Requested model was `gpt-6-astra`; response declared `gpt-5.6-luna`. Protocol acceptance passed and model acceptance failed. This run covers plain text; the Pi runner covers the two-request tool cycle.

The updated Pi runner was also exercised on 2026-09-20: two HTTP 200 responses, valid tool arguments, successful tool-result continuation, exact final text, and `response.completed` for each request. Neither request contained `originator` or turn metadata at gateway ingress. Both requested `gpt-6-astra` and both responses declared `gpt-5.6-luna`; the runner correctly exited with failure while reporting protocol success separately.

### What Pi 0.85.1 actually does

- The native OAuth authorization flow in `dist/auth/oauth/openai-codex.js` adds `originator=pi` to the authorization URL (along with PKCE/state parameters).
- The native `openai-codex-responses` adapter sets Bearer authorization, `chatgpt-account-id`, `originator=pi`, and the Pi User-Agent. SSE sets `session-id` and `x-client-request-id` when a session is supplied; WebSocket requests also carry correlation IDs.
- It does not generate `x-codex-turn-metadata` or default `client_metadata`. It starts from caller-supplied model/option headers, so an explicitly supplied metadata header is retained. Absence by default is not an automatic deletion rule.
- It constructs a Responses body from Pi's message context: top-level `instructions`, converted `input`, tools and tool results, `store=false`, `stream=true`, encrypted reasoning inclusion, cache key, and reasoning options. Tool call/item IDs are normalized for the Responses schema. It is not a general proxy that takes an arbitrary Codex Client request and relabels it.
- Its WebSocket path can reuse connection state with `previous_response_id` and delta input when the cached prefix matches. Full input and SSE fallback are separate paths.
- The product's current Pi configuration uses standard `openai-responses` with a gateway API key. That adapter does not add `originator=pi` by default. The gateway separately owns the imported upstream OAuth session.

Sub2API's existing `openai_codex_fingerprint.go` rewrites selected fields when its fingerprint mode is enabled and retains unspecified metadata fields. It does not globally remove turn metadata. No identity-rewrite behavior was added by this integration.

`npm test --prefix tools/pi-integration` covers missing/mixed/wrong response models, secret-free evidence, malformed/embedded metadata, and SSE observations. It also executes the pinned native Pi adapter against an intercepted fetch with a synthetic token: default metadata is absent, explicitly supplied metadata survives, `originator=pi` and native body fields are generated. This fixture makes no network call and is not proof of live native Pi OAuth authorization.

## Native runtime extension

The standard API-key Pi configuration remains available. The newer **Native Pi** account authorization and gateway route are documented in [runtime/pi/README.md](../../runtime/pi/README.md). They use the pinned native Pi SDK for authorization, refresh and execution, with explicit owner binding and cached WebSocket continuation. The strict passive response observer is shared with this runner. Consult that document for current live acceptance; the older HTTP-only scope above describes the earlier deployment.
