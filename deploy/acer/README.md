# Acer Sub2API deployment

The Acer site uses an isolated Docker Compose project at
`/home/ubuntu/services/sub2api-acer`, private credentials and configuration,
PostgreSQL, Redis, the CPA runtime, and a Cloudflare Tunnel. Keep production
secrets, database backups, and the generated Compose file out of Git.

## Account routing

Each business account has its own Sub2API groups, limits, and usage. The
internal CPA provisioning connection is excluded from business account
listings. Credential import and explicit synchronization must preserve existing
account disablement and group selection; importing the same credential twice
must not create a second identity.

The trusted account identity header is set by Sub2API after removing client
overrides. CPA account binding must select that identity before using session
affinity, and a missing identity must fail rather than route to another
credential. Keep the account binding patch and its regression tests tied to
the exact CPA image source used in deployment.

## Retired state collector

The separate 292/312 collector and managed-state CPA patch are retired. Before
switching to a release built from this tree, stop and disable the old
`sub2api-cpa-state.service`, remove its private snapshot and collector-specific
environment/mount wiring, and rebuild the CPA image without the managed-state
patch. Keep a backup of the previous image and Compose configuration for
rollback. The Sub2API database migration removes only legacy collector
settings and collector keys in account metadata; it leaves business accounts,
usage records, and audit logs intact.

## Release build and acceptance

Build the frontend before the Go server, then compile the server with
`go build -tags embed`. A server built without `embed` can pass `/health` while
the dashboard and every client-side route return 404. Before switching the
Cloudflare route, check `/`, `/login`, and `/admin/accounts` for HTML, then
check `/health`, `/v1/models`, and a real Responses request through the
selected business group. Keep the previous image and Compose configuration
until these checks pass.

After deployment, verify the tunnel routes to Acer, the dashboard loads, an
admin account can be enabled and disabled, and a test request reaches its
selected CPA identity. A healthy homepage alone does not prove model routing.
