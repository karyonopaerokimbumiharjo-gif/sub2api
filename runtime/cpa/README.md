# CPA runtime upgrade

The LAX gateway uses CLIProxyAPI v8.0.8 (`fd48ea6840f5572deb53aeb5657740937ac9daaa`) with the small account-pinning and model quota-scope patch in `patches/v8.0.8-sub2.patch`.

Apply the patch to that stable tag and build `./cmd/server` with Go 1.27.0, `CGO_ENABLED=0`, `GOOS=linux` and `GOARCH=amd64`. The production candidate identifies itself as `8.0.8-lax.1`, commit `0067344019322a500b5bb24b2d97d3c4e1957b3a`.

The removed Excel/Basis Points backend is not included. This static build supports native providers and Codex Images, but does not load dynamic plugins. Preserve the original OAuth files and management credentials. Existing `/v0/management` reads remain available during migration to v8.

Before deploying, verify the selected credential IDs, native Responses and Images execution, management endpoints, and backup/rollback paths. A successful compilation or health response alone does not establish upstream account/model access.
