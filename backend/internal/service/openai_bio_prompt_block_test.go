package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBioPromptBlockKeysAreUserScopedAndFormattingStable(t *testing.T) {
	base := BioPromptBlockKeys(101, 0, "openai", "bio_policy", "", "Review this BIO dataset: source, version, and LICENSE.")
	formatted := BioPromptBlockKeys(101, 0, "openai", "bio_policy", "", "  review THIS bio dataset -- source / version / and license  ")
	otherUser := BioPromptBlockKeys(202, 0, "openai", "bio_policy", "", "Review this BIO dataset: source, version, and LICENSE.")

	require.Len(t, base, 1)
	require.Equal(t, base, formatted)
	require.NotEqual(t, base, otherUser)
}

func TestBioPromptBlockKeysPreferUserAndIncludeExactHash(t *testing.T) {
	keys := BioPromptBlockKeys(101, 55, "openai", "bio_policy", "ABCDEF", "prompt")
	require.Len(t, keys, 2)
	require.NotEqual(t, keys[0], keys[1])
	require.Equal(t, keys, BioPromptBlockKeys(101, 999, "openai", "bio_policy", "abcdef", "prompt"), "API key changes must not split one user's block")
	require.NotEqual(t, keys, BioPromptBlockKeys(102, 55, "openai", "bio_policy", "abcdef", "prompt"))
	require.NotEqual(t, keys, BioPromptBlockKeys(101, 55, "other", "bio_policy", "abcdef", "prompt"))
	require.NotEqual(t, keys, BioPromptBlockKeys(101, 55, "openai", "other_policy", "abcdef", "prompt"))
}

func TestBioPromptBlockKeysRequireIdentityAndPrompt(t *testing.T) {
	require.Nil(t, BioPromptBlockKeys(0, 0, "openai", "bio_policy", "hash", "prompt"))
	require.Empty(t, BioPromptBlockKeys(1, 0, "openai", "bio_policy", "", "  --  "))
}

type bioPromptTestCache struct {
	comboCacheAndStore
	blocked map[string]bool
	ttl     time.Duration
}

var _ GatewayCache = (*bioPromptTestCache)(nil)
var _ BioPromptBlockStore = (*bioPromptTestCache)(nil)

func (c *bioPromptTestCache) SetBioPromptBlocked(_ context.Context, key string, ttl time.Duration) error {
	if c.blocked == nil {
		c.blocked = make(map[string]bool)
	}
	c.blocked[key] = true
	c.ttl = ttl
	return nil
}

func (c *bioPromptTestCache) IsBioPromptBlocked(_ context.Context, keys []string) (bool, error) {
	for _, key := range keys {
		if c.blocked[key] {
			return true, nil
		}
	}
	return false, nil
}

func TestBioPromptBlockRoundTripAndTTL(t *testing.T) {
	settingSvc := &SettingService{settingRepo: &fakeSettingRepo{vals: map[string]string{
		SettingKeyBioPromptBlockEnabled:    "true",
		SettingKeyBioPromptBlockTTLSeconds: "90",
	}}}
	cache := &bioPromptTestCache{}
	svc := &OpenAIGatewayService{cache: cache, settingService: settingSvc}
	keys := BioPromptBlockKeys(101, 0, "openai", "bio_policy", "abc", "same prompt")

	require.False(t, svc.IsBioPromptBlocked(context.Background(), keys))
	svc.MarkBioPromptBlocked(context.Background(), keys)
	require.True(t, svc.IsBioPromptBlocked(context.Background(), keys))
	require.Equal(t, 90*time.Second, cache.ttl)
	require.False(t, svc.IsBioPromptBlocked(context.Background(), BioPromptBlockKeys(202, 0, "openai", "bio_policy", "abc", "same prompt")))
}

func TestBioPromptBlockRuntimeAcceptsNilContext(t *testing.T) {
	settingSvc := &SettingService{settingRepo: &fakeSettingRepo{vals: map[string]string{
		SettingKeyBioPromptBlockEnabled: "true",
	}}}
	enabled, ttl := settingSvc.GetBioPromptBlockRuntime(context.Background())
	require.True(t, enabled)
	require.Equal(t, 30*24*time.Hour, ttl)
}
