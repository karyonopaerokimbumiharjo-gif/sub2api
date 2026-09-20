package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

type BioPromptBlockStore interface {
	SetBioPromptBlocked(ctx context.Context, key string, ttl time.Duration) error
	IsBioPromptBlocked(ctx context.Context, keys []string) (bool, error)
}

// BioPromptBlockKeys returns a user-isolated exact audit hash and a normalized
// text fingerprint. The normalized key catches harmless formatting/case/space
// changes without attempting broad semantic similarity across different
// prompts or users.
func BioPromptBlockKeys(userID, apiKeyID int64, provider, policyCode, promptHash, fullPrompt string) []string {
	scope := ""
	if userID > 0 {
		scope = "user:" + strconv.FormatInt(userID, 10)
	} else if apiKeyID > 0 {
		scope = "key:" + strconv.FormatInt(apiKeyID, 10)
	}
	if scope == "" {
		return nil
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "openai"
	}
	policyCode = strings.ToLower(strings.TrimSpace(policyCode))
	if policyCode == "" {
		policyCode = "bio_policy"
	}
	scope += "\x00provider:" + provider + "\x00policy:" + policyCode
	keys := make([]string, 0, 2)
	if exact := strings.ToLower(strings.TrimSpace(promptHash)); exact != "" {
		keys = append(keys, bioPromptScopedDigest(scope, "exact", exact))
	}
	if normalized := normalizeBioPromptFingerprintText(fullPrompt); normalized != "" {
		sum := sha256.Sum256([]byte(normalized))
		keys = append(keys, bioPromptScopedDigest(scope, "normalized", hex.EncodeToString(sum[:])))
	}
	return keys
}

func normalizeBioPromptFingerprintText(value string) string {
	var builder strings.Builder
	spacePending := false
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			if spacePending && builder.Len() > 0 {
				_ = builder.WriteByte(' ')
			}
			spacePending = false
			_, _ = builder.WriteRune(r)
			continue
		}
		spacePending = true
	}
	return strings.TrimSpace(builder.String())
}

func bioPromptScopedDigest(scope, kind, fingerprint string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + kind + "\x00" + fingerprint))
	return hex.EncodeToString(sum[:])
}

func (s *OpenAIGatewayService) bioPromptBlockStore() BioPromptBlockStore {
	if s == nil || s.cache == nil {
		return nil
	}
	store, _ := s.cache.(BioPromptBlockStore)
	return store
}

func (s *OpenAIGatewayService) BioPromptBlockRuntime(ctx context.Context) (bool, time.Duration) {
	if s == nil || s.settingService == nil {
		return false, 30 * 24 * time.Hour
	}
	return s.settingService.GetBioPromptBlockRuntime(ctx)
}

func (s *OpenAIGatewayService) MarkBioPromptBlocked(ctx context.Context, keys []string) {
	if len(keys) == 0 {
		return
	}
	enabled, ttl := s.BioPromptBlockRuntime(ctx)
	if !enabled {
		return
	}
	store := s.bioPromptBlockStore()
	if store == nil {
		return
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if err := store.SetBioPromptBlocked(ctx, key, ttl); err != nil {
			logger.LegacyPrintf("service.openai_gateway", "bio prompt block write failed: err=%v", err)
		}
	}
}

func (s *OpenAIGatewayService) IsBioPromptBlocked(ctx context.Context, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	enabled, _ := s.BioPromptBlockRuntime(ctx)
	if !enabled {
		return false
	}
	store := s.bioPromptBlockStore()
	if store == nil {
		return false
	}
	blocked, err := store.IsBioPromptBlocked(ctx, keys)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "bio prompt block read failed: err=%v", err)
		return false
	}
	return blocked
}
