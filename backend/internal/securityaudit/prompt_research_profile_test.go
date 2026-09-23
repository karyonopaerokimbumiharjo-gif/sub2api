package securityaudit

import (
	"context"
	"github.com/stretchr/testify/require"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestResearchApprovalRequiresExactVerifiedScopeAndExpiry(t *testing.T) {
	now := time.Now()
	v := ResearchApproval{UserID: 1, APIKeyID: 2, Organization: "Verified lab", Purpose: "Literature review", Verification: "internal-record-42", Projects: []string{"review"}, Resources: []string{"public-citations"}, Tools: []string{"none"}, ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, validateResearchApproval(v, now))
	for _, mutate := range []func(*ResearchApproval){func(v *ResearchApproval) { v.UserID = 0 }, func(v *ResearchApproval) { v.Verification = "" }, func(v *ResearchApproval) { v.Tools = []string{"*"} }, func(v *ResearchApproval) { v.ExpiresAt = now }, func(v *ResearchApproval) { v.ExpiresAt = now.Add(91 * 24 * time.Hour) }, func(v *ResearchApproval) { v.Resources = nil }} {
		bad := v
		mutate(&bad)
		require.Error(t, validateResearchApproval(bad, now))
	}
}

func TestResearchProfilePostgresApprovalRevocationAndEvidence(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	_, err := db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'; ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ; ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS user_id BIGINT; ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'; ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;`)
	require.NoError(t, err)
	migration, err := os.ReadFile("../../migrations/246_verified_research_profiles.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = db.Exec(string(migration))
		require.NoError(t, err)
	}
	admin := insertIdentity(t, db, "users")
	user := insertIdentity(t, db, "users")
	key := insertIdentity(t, db, "api_keys")
	_, err = db.Exec(`UPDATE users SET role='admin' WHERE id=$1`, admin)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE api_keys SET user_id=$1 WHERE id=$2`, user, key)
	require.NoError(t, err)
	svc := &PromptService{repo: NewPostgreSQLRepository(db)}
	ctx := context.Background()
	v := ResearchApproval{UserID: user, APIKeyID: key, Organization: "Verified lab", Purpose: "Citation review", Verification: "internal:42", Projects: []string{"review"}, Resources: []string{"public"}, Tools: []string{"none"}, ExpiresAt: time.Now().Add(time.Hour)}
	_, err = svc.ApproveResearchProfile(ctx, v, user)
	require.Error(t, err)
	p, err := svc.ApproveResearchProfile(ctx, v, admin)
	require.NoError(t, err)
	require.Equal(t, admin, p.ApprovedBy)
	require.Equal(t, p.ID, svc.activeResearchProfile(ctx, user, key))
	require.Zero(t, svc.activeResearchProfile(ctx, admin, key))
	snapshot := integrationSnapshot("research")
	snapshot.ResearchProfileID = p.ID
	r := integrationResult(EventPass)
	applyBioTier(r, "B2")
	event, err := svc.repo.RecordBlocking(ctx, snapshot, 1, r, true)
	require.NoError(t, err)
	require.Equal(t, "review_required", event.AuditStatus)
	require.Equal(t, EventReviewRequired, event.Decision)
	require.Equal(t, strconv.FormatInt(p.ID, 10), event.ScannerEvidence["research_profile_id"])
	_, err = svc.RevokeResearchProfile(ctx, p.ID, admin, "scope ended")
	require.NoError(t, err)
	require.Zero(t, svc.activeResearchProfile(ctx, user, key))
	rows, err := svc.ListResearchProfiles(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].RevokedAt)
}
