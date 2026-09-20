package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
)

// CyberSessionBlockStore 是 cyber 会话屏蔽表的存取接口。
// repository 层 gatewayCache 附带实现（类型断言探测接入，不改 GatewayCache
// 共享接口）；测试 stub 不实现时屏蔽能力自动降级关闭。
type CyberSessionBlockStore interface {
	SetCyberSessionBlocked(ctx context.Context, scopeKey string, keys []string, ttl time.Duration) error
	IsCyberSessionScopeActive(ctx context.Context, scopeKey string) (bool, error)
	FindCyberSessionBlocked(ctx context.Context, keys []string) (string, error)
}

// SecurityAuditRevocationStore persists revocation independently from Redis.
type SecurityAuditRevocationStore interface {
	SaveSecurityAuditRevocations(context.Context, []string) error
	LoadSecurityAuditRevocations(context.Context, []string) (map[string]bool, error)
}

func (s *OpenAIGatewayService) securityAuditRevocationStore() SecurityAuditRevocationStore {
	if s == nil || s.settingService == nil {
		return nil
	}
	store, _ := s.settingService.settingRepo.(SecurityAuditRevocationStore)
	return store
}

const cyberSessionTranscriptLookupOverflowBlockKey = "transcript_lookup_limit_exceeded"

const securityAuditSessionBlockNamespace = "prompt_guard:"

func securityAuditSessionBlockKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	return securityAuditSessionBlockNamespace + key
}

func securityAuditSessionBlockKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		namespaced := securityAuditSessionBlockKey(key)
		if namespaced == "" {
			continue
		}
		if _, ok := seen[namespaced]; ok {
			continue
		}
		seen[namespaced] = struct{}{}
		out = append(out, namespaced)
	}
	return out
}

// CyberSessionExplicitBlockKey returns an inexpensive exact key when the
// client supplies a stable session signal.
func CyberSessionExplicitBlockKey(apiKeyID int64, c *gin.Context, body []byte) string {
	return hashCyberSessionBlockKey(apiKeyID, explicitOpenAISessionID(c, body))
}

// CyberSessionPreviousResponseBlockKey derives a stable block key from a valid
// Responses previous_response_id. This closes the gap where a client continues
// a rejected conversation using only resp_* without any explicit session header
// or prompt_cache_key.
func CyberSessionPreviousResponseBlockKey(apiKeyID int64, body []byte) string {
	id := strings.TrimSpace(openAIRequestPayloadView(body).Get("previous_response_id").String())
	if ClassifyOpenAIPreviousResponseIDKind(id) != OpenAIPreviousResponseIDKindResponseID {
		return ""
	}
	return hashCyberSessionBlockKey(apiKeyID, "previous_response_id:"+id)
}

// CyberSessionTranscriptBlockKeys returns the exact full-request key followed
// by an optional rewrite-tolerant context key. The latter is emitted only after
// model-generated history has been observed.
func CyberSessionTranscriptBlockKeys(apiKeyID int64, body []byte) []string {
	derived := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, body)
	if len(derived.lookupKeys) == 0 {
		return nil
	}
	keys := []string{derived.lookupKeys[len(derived.lookupKeys)-1]}
	if derived.preLatestUserKey != "" && derived.preLatestUserKey != keys[0] {
		keys = append(keys, derived.preLatestUserKey)
	}
	return keys
}

func CyberSessionTranscriptLookupKeys(apiKeyID int64, body []byte) []string {
	return deriveOpenAICyberTranscriptBlockKeys(apiKeyID, body).lookupKeys
}

// CyberSessionScopeKey is a coarse, non-blocking fingerprint used only to
// avoid transcript parsing and MGET for sources that never produced a hit.
func CyberSessionScopeKey(apiKeyID int64, clientIP, userAgent string) string {
	if apiKeyID <= 0 {
		return ""
	}
	raw := "cyber-scope:v1|api_key=" + strconv.FormatInt(apiKeyID, 10) +
		"|ip=" + strings.TrimSpace(clientIP) +
		"|ua=" + NormalizeSessionUserAgent(userAgent)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func hashCyberSessionBlockKey(apiKeyID int64, raw string) string {
	if raw == "" {
		return ""
	}
	isolated := isolateOpenAISessionID(apiKeyID, raw)
	sum := sha256.Sum256([]byte(isolated))
	return hex.EncodeToString(sum[:])
}

// cyberSessionBlockStore 探测 cache 是否具备屏蔽存储能力。
// 注意：若未来以装饰器包装 GatewayCache（如日志/指标装饰器），该装饰器必须同时实现
// CyberSessionBlockStore，否则会话屏蔽能力将静默降级关闭
// （编译断言 var _ service.CyberSessionBlockStore = (*gatewayCache)(nil) 只覆盖
// *gatewayCache 本体，无法覆盖其外层包装）。
func (s *OpenAIGatewayService) cyberSessionBlockStore() CyberSessionBlockStore {
	if s == nil || s.cache == nil {
		return nil
	}
	store, ok := s.cache.(CyberSessionBlockStore)
	if !ok {
		return nil
	}
	return store
}

// CyberSessionBlockRuntime 返回 (开关, TTL)。开关默认关。
// 委托给 SettingService.GetCyberSessionBlockRuntime，进程内缓存避免热路径 DB 往返。
func (s *OpenAIGatewayService) CyberSessionBlockRuntime(ctx context.Context) (bool, time.Duration) {
	if s == nil || s.settingService == nil {
		return false, time.Hour
	}
	return s.settingService.GetCyberSessionBlockRuntime(ctx)
}

// MarkCyberSessionBlocked 把会话写入屏蔽表（写入点：cyber 命中后）。
// 开关关闭、key 为空或存储不可用时静默跳过。
func (s *OpenAIGatewayService) MarkCyberSessionBlocked(ctx context.Context, scopeKey string, keys []string) {
	if s == nil || len(keys) == 0 {
		return
	}
	enabled, ttl := s.CyberSessionBlockRuntime(ctx)
	if !enabled {
		return
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return
	}
	if err := store.SetCyberSessionBlocked(ctx, scopeKey, keys, ttl); err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block write failed: err=%v", err)
	}
}

// InvalidateSecurityAuditSession invalidates a conversation after a blocking
// security-audit verdict. Unlike the optional upstream cyber-policy switch, this
// path is intentionally unconditional: a blocking prompt-guard verdict must not
// be followed by continuation of the same local conversation.
//
// It (1) writes the conversation block keys, (2) removes sticky account binding,
// (3) drops WS turn-state/session connection binding, and (4) drops the current
// previous_response_id account/connection binding when present. The remote
// upstream response object may still physically exist, but this gateway refuses
// reuse of the blocked conversation and requires a new session.
func (s *OpenAIGatewayService) InvalidateSecurityAuditSession(
	ctx context.Context,
	groupID *int64,
	c *gin.Context,
	body []byte,
	scopeKey string,
	keys []string,
) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Prompt-guard revocations are durable until explicitly removed. The
	// optional upstream cyber cooldown must not silently reopen an audit block.
	ttl := time.Duration(0)
	var firstErr error
	namespacedKeys := securityAuditSessionBlockKeys(keys)
	namespacedScope := securityAuditSessionBlockKey(scopeKey)
	if durable := s.securityAuditRevocationStore(); durable != nil && len(namespacedKeys) > 0 {
		keys := append([]string(nil), namespacedKeys...)
		if namespacedScope != "" {
			keys = append(keys, namespacedScope)
		}
		if err := durable.SaveSecurityAuditRevocations(ctx, keys); err != nil {
			firstErr = err
		}
	}

	if store := s.cyberSessionBlockStore(); store != nil && len(namespacedKeys) > 0 {
		if err := store.SetCyberSessionBlocked(ctx, namespacedScope, namespacedKeys, ttl); err != nil {
			firstErr = err
			logger.LegacyPrintf("service.openai_gateway", "security audit session block write failed: err=%v", err)
		}
	} else {
		firstErr = errors.New("security audit session invalidation storage or identity unavailable")
	}

	sessionHash := s.GenerateSessionHash(c, body)
	if sessionHash != "" {
		if err := s.deleteStickySessionAccountID(ctx, groupID, sessionHash); err != nil && firstErr == nil {
			firstErr = err
		}
		store := s.getOpenAIWSStateStore()
		store.DeleteSessionTurnState(derefGroupID(groupID), sessionHash)
		store.DeleteSessionConn(derefGroupID(groupID), sessionHash)
	}

	previousID := strings.TrimSpace(openAIRequestPayloadView(body).Get("previous_response_id").String())
	if ClassifyOpenAIPreviousResponseIDKind(previousID) == OpenAIPreviousResponseIDKindResponseID {
		store := s.getOpenAIWSStateStore()
		store.DeleteResponseConn(previousID)
		if err := store.DeleteResponseAccount(ctx, derefGroupID(groupID), previousID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// FindSecurityAuditSessionInvalidatedForRequest checks the independent prompt-guard
// invalidation namespace. It deliberately ignores cyber_session_block_enabled so
// a blocking audit verdict cannot be re-enabled by an older persisted setting.
const SecurityAuditSessionStoreUnavailable = "security_audit_session_store_unavailable"

func (s *OpenAIGatewayService) FindSecurityAuditSessionInvalidatedForRequest(ctx context.Context, apiKeyID int64, c *gin.Context, body []byte, clientIP, userAgent string) string {
	if s == nil {
		return ""
	}
	if durable := s.securityAuditRevocationStore(); durable != nil {
		direct := securityAuditSessionBlockKeys([]string{CyberSessionPreviousResponseBlockKey(apiKeyID, body), CyberSessionExplicitBlockKey(apiKeyID, c, body)})
		transcript := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, body)
		keys := append(direct, securityAuditSessionBlockKeys(transcript.lookupKeys)...)
		scope := securityAuditSessionBlockKey(CyberSessionScopeKey(apiKeyID, clientIP, userAgent))
		query := append([]string(nil), keys...)
		if scope != "" {
			query = append(query, scope)
		}
		found, err := durable.LoadSecurityAuditRevocations(ctx, query)
		if err != nil {
			return SecurityAuditSessionStoreUnavailable
		}
		for _, key := range keys {
			if found[key] {
				return key
			}
		}
		if transcript.lookupKeysTruncated && found[scope] {
			return securityAuditSessionBlockKey(cyberSessionTranscriptLookupOverflowBlockKey)
		}
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return ""
	}
	direct := securityAuditSessionBlockKeys([]string{
		CyberSessionPreviousResponseBlockKey(apiKeyID, body),
		CyberSessionExplicitBlockKey(apiKeyID, c, body),
	})
	if len(direct) > 0 {
		key, err := store.FindCyberSessionBlocked(ctx, direct)
		if err != nil {
			logger.LegacyPrintf("service.openai_gateway", "security audit direct session read failed: err=%v", err)
			return SecurityAuditSessionStoreUnavailable
		}
		if key != "" {
			return key
		}
	}
	scopeKey := securityAuditSessionBlockKey(CyberSessionScopeKey(apiKeyID, clientIP, userAgent))
	if scopeKey == "" {
		return ""
	}
	active, err := store.IsCyberSessionScopeActive(ctx, scopeKey)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "security audit session scope read failed: err=%v", err)
		return SecurityAuditSessionStoreUnavailable
	}
	if !active {
		return ""
	}
	transcript := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, body)
	if transcript.lookupKeysTruncated {
		return securityAuditSessionBlockKey(cyberSessionTranscriptLookupOverflowBlockKey)
	}
	keys := securityAuditSessionBlockKeys(transcript.lookupKeys)
	if len(keys) == 0 {
		return ""
	}
	key, err := store.FindCyberSessionBlocked(ctx, keys)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "security audit session block batch read failed: err=%v", err)
		return SecurityAuditSessionStoreUnavailable
	}
	return key
}

// FindCyberSessionBlockedForRequest applies explicit-first lookup followed by
// scope-gated transcript matching. All failures remain fail-open.
func (s *OpenAIGatewayService) FindCyberSessionBlockedForRequest(ctx context.Context, apiKeyID int64, c *gin.Context, body []byte, clientIP, userAgent string) string {
	enabled, _ := s.CyberSessionBlockRuntime(ctx)
	if !enabled {
		return ""
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return ""
	}
	directKeys := make([]string, 0, 2)
	if previousKey := CyberSessionPreviousResponseBlockKey(apiKeyID, body); previousKey != "" {
		directKeys = append(directKeys, previousKey)
	}
	if explicitKey := CyberSessionExplicitBlockKey(apiKeyID, c, body); explicitKey != "" {
		directKeys = append(directKeys, explicitKey)
	}
	if len(directKeys) > 0 {
		key, err := store.FindCyberSessionBlocked(ctx, directKeys)
		if err != nil {
			logger.LegacyPrintf("service.openai_gateway", "cyber direct session read failed: err=%v", err)
			return ""
		}
		if key != "" {
			return key
		}
	}
	scopeKey := CyberSessionScopeKey(apiKeyID, clientIP, userAgent)
	active, err := store.IsCyberSessionScopeActive(ctx, scopeKey)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session scope read failed: err=%v", err)
		return ""
	}
	if !active {
		return ""
	}
	transcript := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, body)
	if transcript.lookupKeysTruncated {
		// Once the coarse scope is active, silently dropping old candidates would
		// let a blocked client evade prefix matching by appending dummy items.
		return cyberSessionTranscriptLookupOverflowBlockKey
	}
	keys := transcript.lookupKeys
	if len(keys) == 0 {
		return ""
	}
	key, err := store.FindCyberSessionBlocked(ctx, keys)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block batch read failed: err=%v", err)
		return ""
	}
	return key
}
