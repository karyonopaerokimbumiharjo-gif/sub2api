package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

const (
	openAICodexPersonalBlocks = 10
	openAICodexTeamBlocks     = 12
	openAICodexPersonalLength = 292
	openAICodexTeamLength     = 332
)

type openAICodexStateShape struct {
	Blocks      int
	IssuedAt    time.Time
	Fingerprint string
	Length      int
}

type openAICodexStatePolicy struct {
	PlanClass      string
	ExpectedBlocks int
	NominalLength  int
	TTL            time.Duration
	RefreshBefore  time.Duration
}

func parseOpenAICodexStateShape(value string) (openAICodexStateShape, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\r\n\t ") {
		return openAICodexStateShape{}, errors.New("invalid state encoding")
	}
	core := strings.TrimRight(value, "=")
	if len(value)-len(core) > 2 {
		return openAICodexStateShape{}, errors.New("invalid state padding")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(core)
	if err != nil || len(raw) < 73 || raw[0] != 0x80 || (len(raw)-57)%16 != 0 {
		return openAICodexStateShape{}, errors.New("unrecognized state envelope")
	}
	issuedUnix := binary.BigEndian.Uint64(raw[1:9])
	if issuedUnix < 1577836800 || issuedUnix >= 4102444800 {
		return openAICodexStateShape{}, errors.New("state timestamp out of range")
	}
	sum := sha256.Sum256([]byte(value))
	return openAICodexStateShape{
		Blocks:      (len(raw) - 57) / 16,
		IssuedAt:    time.Unix(int64(issuedUnix), 0).UTC(),
		Fingerprint: hex.EncodeToString(sum[:8]),
		Length:      len(value),
	}, nil
}

func openAICodexPlanClass(account *Account) (string, bool) {
	if account == nil {
		return "unknown", false
	}
	switch strings.ToLower(strings.TrimSpace(account.GetCredential("plan_type"))) {
	case "team", "business", "enterprise", "edu", "education":
		return "team", true
	case "":
		return "unknown", false
	default:
		return "personal", true
	}
}

func openAICodexPolicyForAccount(account *Account, cfg config.OpenAICodexTicketConfig) openAICodexStatePolicy {
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	refresh := time.Duration(cfg.RefreshBeforeSeconds) * time.Second
	if refresh <= 0 {
		refresh = 10 * time.Minute
	}
	class, known := openAICodexPlanClass(account)
	policy := openAICodexStatePolicy{
		PlanClass:      class,
		ExpectedBlocks: openAICodexPersonalBlocks,
		NominalLength:  openAICodexPersonalLength,
		TTL:            ttl,
		RefreshBefore:  refresh,
	}
	if known && class == "team" {
		policy.ExpectedBlocks = openAICodexTeamBlocks
		policy.NominalLength = openAICodexTeamLength
		return policy
	}
	// Preserve an operator's legacy personal target length only when it maps to
	// a known state shape. A state is never promoted to Team merely because its
	// string happens to be longer.
	switch cfg.TargetLength {
	case openAICodexTeamLength:
		// Do not infer Team for an unknown/personal account.
	case openAICodexPersonalLength, 0:
	default:
		policy.NominalLength = cfg.TargetLength
	}
	return policy
}

func openAICodexStateAccepted(shape openAICodexStateShape, policy openAICodexStatePolicy, now time.Time) bool {
	if shape.Blocks != policy.ExpectedBlocks || shape.Length <= 0 || shape.IssuedAt.IsZero() {
		return false
	}
	if policy.NominalLength > 0 && shape.Length != policy.NominalLength {
		return false
	}
	if shape.IssuedAt.After(now.Add(30 * time.Second)) {
		return false
	}
	// Subtract a small safety margin so a state is never admitted at the exact
	// TTL boundary.
	return now.Before(shape.IssuedAt.Add(policy.TTL - 30*time.Second))
}

func openAICodexCredentialFingerprint(account *Account) string {
	if account == nil {
		return ""
	}
	material := strings.TrimSpace(account.GetCredential("refresh_token"))
	if material == "" {
		material = strings.TrimSpace(account.GetCredential("access_token"))
	}
	if material == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:8])
}

func openAICodexRouteFingerprint(proxyURL, provider string) string {
	value := strings.TrimSpace(provider) + "\x00" + strings.TrimSpace(proxyURL)
	if strings.Trim(value, "\x00") == "" {
		return "direct"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
