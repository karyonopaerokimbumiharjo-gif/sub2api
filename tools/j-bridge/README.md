# Authorized local J tool bridge

This bridge executes only an operator-owned manifest through local MCP servers.
The gateway cannot send executable names, command arguments or environment values.
Jev and the selected base model use the same grant. No separate local agent runs.

Requires Node 24 or newer. Install dependencies with `npm ci --ignore-scripts`.
Create a manifest outside the repository (absolute executable and workspace paths):

```json
{
  "device_id": "my-authorized-device",
  "workspace": "/absolute/authorized/workspace",
  "servers": {
    "files": {"command": "/absolute/node", "args": ["/absolute/trusted-mcp-server.mjs"], "env": []}
  },
  "tools": [{
    "name": "read_fixture", "server": "files", "risk": "R1",
    "parameters": {"type":"object","properties":{"file":{"type":"string","enum":["note.txt"]}},"required":["file"],"additionalProperties":false}
  }]
}
```

The pinned schema must equal the server's discovered input schema. Limit files,
URLs and other resources in that schema and in the trusted MCP server itself.
A working directory is **not** an OS sandbox; install only trusted MCP servers.
Each grant runs its own bridge process. Do not share a browser profile or external
state directory across users. MCP processes are closed after each invocation.

Set `SUB2API_BASE_URL` and `SUB2API_API_KEY` in your local environment, then run:

```sh
node cli.mjs /absolute/manifest.json unique-session-id unique-task-id
```

Enable J on this Key in the gateway's “API 密钥 → 使用” dialog first. The bridge
prints only its grant ID, session ID and expiry. Keep its grant secret in memory.
For the matching `POST /v1/responses`, send:

- `model`: an available `<base-model>-j` alias.
- `X-Sub2API-Tool-Grant`: the printed grant ID.
- `session_id`: the same session value in the supported request header.
- `tools`: exactly the function schemas in the manifest, without server/command fields.
- `Idempotency-Key`: exactly the task ID supplied to the bridge; reuse only to retrieve its result.

A grant is bound to one user, key, device, session and HTTP task. A subsequent HTTP
turn needs a new grant. Another task or device cannot reuse an old authorization.

R0/R1 tools use the explicit manifest authorization. R2/R3 calls require an
interactive terminal approval for that exact call and arguments. R4 is rejected.
No shell command is synthesized from model output. No gateway API key is passed
to the MCP process. Only explicitly selected environment variables are forwarded.

An R2 manifest must also list the relative files it may change in
`rollback_files`. Before execution the bridge stores a private snapshot outside
the workspace, records hashes and modes, and refuses restore when an operator or
another process changed a file afterward. `node rollback.mjs SNAPSHOT_DIRECTORY`
is an explicit operator action; a failed or uncertain tool call is recorded as
unknown and is never automatically replayed or reverted.

Grants expire after 15 minutes. Revocation, request cancellation, loss of the
lease check, timeout or output overflow terminates the call. An uncertain side
effect is never retried. The operator must inspect its effect before a new task.
Ctrl-C revokes the grant and stops the local child. This cannot roll back an
effect a tool already committed.

Ordinary Responses clients can also execute returned functions themselves,
without this bridge. Both full `input` history and gateway-owned
`previous_response_id` continuation are supported on HTTP. J WebSocket transport
is not implemented; base-model native WebSocket/compaction remains available.

Validation: `npm test` runs a real local MCP file-read fixture plus schema,
permission, revocation and cancellation tests. No production credentials are used.
