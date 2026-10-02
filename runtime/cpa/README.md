# CPA runtime upgrade

The LAX gateway uses CLIProxyAPI v8.0.11 (`e2bff0107bb307337aaa19018ccddd55f64253d5`) with the small account-pinning and model quota-scope patch in `patches/v8.0.11-sub2.patch`.

Apply the patch to that stable tag and build `./cmd/server` with Go 1.27.0, `CGO_ENABLED=0`, `GOOS=linux` and `GOARCH=amd64`. The production candidate identifies itself as `8.0.11-lax.1`, commit `dd567f8ec798bd9800a34f8d9c258e723d9403ca`.

This release preserves top-level Responses token usage when `service_tier` is present, handles split Gemini usage metadata and maximum-token terminals, and retains shared upstream settings across historical v8 aliases. It also includes the earlier Responses `apply_patch` bridge, client configuration, Gemini signature handling and Antigravity stream-usage corrections. Exact Sub2 credential selection and Spark's independent quota pool remain covered by the local regressions. The older `v8.0.8-sub2.patch` and `v8.0.10-sub2.patch` are retained for reproducing prior candidates.

The removed Excel/Basis Points backend is not included. This static build supports native providers and Codex Images, but does not load dynamic plugins. Preserve the original OAuth files and management credentials. Existing `/v0/management` reads remain available during migration to v8.

Before deploying, verify the selected credential IDs, native Responses and Images execution, management endpoints, and backup/rollback paths. A successful compilation or health response alone does not establish upstream account/model access.
