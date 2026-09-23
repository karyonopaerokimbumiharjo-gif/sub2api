package securityaudit

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestPromptAuditOutputCapturePersistsAndDoesNotClaimFullPass(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	snapshot := integrationSnapshot("partial")
	snapshot.Stage, snapshot.AuditSubject = "output", "output_content_partial"
	snapshot.OutputCapture = &OutputCapture{CapturedBytes: 100, ObservedBytes: 200, Truncated: true, Complete: false, Terminal: "cancelled"}
	event, err := repo.RecordBlocking(ctx, snapshot, 3, integrationResult(EventPass), true)
	require.NoError(t, err)
	require.Equal(t, "partial", event.AuditStatus)
	require.Equal(t, snapshot.OutputCapture, event.Snapshot.OutputCapture)
	detail, err := repo.GetEvent(ctx, event.ID)
	require.NoError(t, err)
	require.Equal(t, event.Snapshot.OutputCapture, detail.Snapshot.OutputCapture)
	page, err := repo.ListEvents(ctx, EventFilter{}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, snapshot.OutputCapture, page.Items[0].Snapshot.OutputCapture)
}

func TestPromptAuditPolicyReviewPreservesProviderEvidenceAndClearsOnlyScope(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	svc := &PromptService{repo: repo, payload: NewRedisPayloadStore(client)}
	ctx := context.Background()
	snapshot := integrationSnapshot("bio")
	snapshot.UserID = insertIdentity(t, db, "users")
	snapshot.TaskFingerprint = "task-fingerprint"
	snapshot.PolicyCacheVersion = 7
	require.NoError(t, svc.RecordUpstreamPolicyFeedback(ctx, snapshot, "bio_policy", "upstream refusal"))
	page, err := repo.ListEvents(ctx, EventFilter{}, 1, 20)
	require.NoError(t, err)
	event := page.Items[0]
	require.Equal(t, EventUpstreamPolicyBlock, event.Decision)
	require.Equal(t, RiskUnknown, event.RiskLevel)
	require.Equal(t, int64(7), event.ConfigVersion)
	require.Empty(t, event.ScannerScores)
	keys := service.BioPromptBlockKeys(snapshot.UserID, 0, snapshot.Provider, "bio_policy", snapshot.TaskFingerprint, snapshot.FullPrompt, 7, snapshot.Model)
	otherKeys := service.BioPromptBlockKeys(snapshot.UserID, 0, snapshot.Provider, "bio_policy", snapshot.TaskFingerprint, snapshot.FullPrompt, 7, "other-model")
	for _, key := range append(keys, otherKeys...) {
		require.NoError(t, client.Set(ctx, service.BioPromptBlockCachePrefix+key, "1", time.Hour).Err())
	}
	_, err = svc.ReviewPolicyEvent(ctx, event.ID, 10, PolicyReviewRequest{Action: "cleared"})
	require.Error(t, err, "a review reason is required")
	reviewed, err := svc.ReviewPolicyEvent(ctx, event.ID, 10, PolicyReviewRequest{Action: "cleared", Reason: "manual false positive review"})
	require.NoError(t, err)
	require.Equal(t, EventUpstreamPolicyBlock, reviewed.Decision)
	require.Equal(t, "cleared", reviewed.ReviewStatus)
	for _, key := range keys {
		require.False(t, mr.Exists(service.BioPromptBlockCachePrefix+key))
	}
	for _, key := range otherKeys {
		require.True(t, mr.Exists(service.BioPromptBlockCachePrefix+key))
	}
	stored, err := repo.GetEvent(ctx, event.ID)
	require.NoError(t, err)
	require.Equal(t, reviewed.PolicyReview, stored.PolicyReview)
	require.Equal(t, "cleared", stored.ReviewStatus)
	// Clearing an event cannot release unrelated CTE/jailbreak rules.
	pass, err := repo.RecordBlocking(ctx, integrationSnapshot("ordinary"), 7, integrationResult(EventCritical), true)
	require.NoError(t, err)
	_, err = svc.ReviewPolicyEvent(ctx, pass.ID, 10, PolicyReviewRequest{Action: "cleared", Reason: "wrong event"})
	require.Error(t, err)
}
