package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	DefaultWorkerCount   = 4
	MaxWorkerCount       = 32
	DefaultQueueCapacity = 32768
	MaxQueueCapacity     = 100000
	DefaultTimeoutMS     = 3000
	MinTimeoutMS         = 100
	MaxTimeoutMS         = 30000
	DefaultInputLimit    = 4000
	// Prompt chunks from one request are scanned concurrently up to this limit.
	// It is deliberately lower than the endpoint bulkheads so a single large
	// prompt cannot consume all audit capacity.
	MinPromptChunkConcurrency      = 1
	DefaultPromptChunkConcurrency  = 4
	MaxPromptChunkConcurrency      = 16
	MaxPromptAuditWhitelistEmails  = 500
	MinInputLimit                  = 128
	MaxInputLimit                  = 100000
	DefaultPayloadTTL              = 30 * time.Minute
	DefaultAdaptiveAllowSampleRate = 5
	DefaultAdaptiveRiskSampleRate  = 100
	DefaultOutputAllowSampleRate   = 5
	DefaultOutputRiskSampleRate    = 100

	BlockingAuditModeFastLatest      = "fast_latest"
	BlockingAuditModeIncrementalFull = "incremental_full"
	BlockingAuditModeFull            = "full"
	BackgroundAuditModeOff           = "off"
)

type SecretEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// ConfigStore is the injectable boundary between hot-path prompt auditing and
// the concrete settings/PostgreSQL/Redis-backed configuration manager.
type ConfigStore interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Active() (ActiveConfig, bool)
	EffectiveMode() Mode
	// BlockingActivationDegraded is true when storage intent requires blocking
	// but no usable blocking snapshot is active (cold start or failed reload).
	// It must stay false when blocking is not intended, even if config is
	// untrusted—otherwise default-off deployments fail closed for all traffic.
	BlockingActivationDegraded() bool
	Public() (PublicConfig, error)
	Save(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error)
	ListPolicyVersions(ctx context.Context, limit int) ([]PromptPolicyVersion, error)
	RollbackPolicy(ctx context.Context, targetConfigVersion, expectedConfigVersion, actorID int64) (PublicConfig, error)
	RuntimeState() (expected int64, active int64, loadedAt *time.Time, loadError string)
	Encrypt(value string) (string, error)
	Decrypt(value string) (string, error)
}

type StorageEndpoint struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	Adapter         string `json:"adapter"`
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	AccountID       int64  `json:"account_id,omitempty"`
	TokenCiphertext string `json:"token_ciphertext,omitempty"`
	TimeoutMS       int    `json:"timeout_ms"`
	InputLimit      int    `json:"input_limit"`
	Enabled         bool   `json:"enabled"`
}

type storageConfig struct {
	Enabled             bool   `json:"enabled"`
	BlockingEnabled     bool   `json:"blocking_enabled"`
	BlockingAuditMode   string `json:"blocking_audit_mode"`
	BackgroundAuditMode string `json:"background_audit_mode"`
	// BlockingLatestTurnOnly is retained for compatibility with old policy
	// snapshots and admin clients. New code uses BlockingAuditMode.
	BlockingLatestTurnOnly      bool     `json:"blocking_latest_turn_only"`
	StorePassEvents             bool     `json:"store_pass_events"`
	AdaptiveEnabled             bool     `json:"adaptive_enabled"`
	AdaptiveCollectWhenDisabled bool     `json:"adaptive_collect_when_disabled"`
	AdaptiveAllowSampleRate     int      `json:"adaptive_allow_sample_rate"`
	AdaptiveRiskSampleRate      int      `json:"adaptive_risk_sample_rate"`
	OutputAuditEnabled          bool     `json:"output_audit_enabled"`
	OutputAllowSampleRate       int      `json:"output_allow_sample_rate"`
	OutputRiskSampleRate        int      `json:"output_risk_sample_rate"`
	Strategy                    string   `json:"strategy"`
	WorkerCount                 int      `json:"worker_count"`
	PromptChunkConcurrency      int      `json:"prompt_chunk_concurrency"`
	QueueCapacity               int      `json:"queue_capacity"`
	Scanners                    []string `json:"scanners"`
	AllGroups                   bool     `json:"all_groups"`
	GroupIDs                    []int64  `json:"group_ids"`
	// WhitelistEmails is retained only to decode legacy policy snapshots. The
	// runtime release authority is User.PromptAuditBypass and this list is not
	// consulted when a request is evaluated.
	WhitelistEmails []string          `json:"whitelist_emails"`
	Endpoints       []StorageEndpoint `json:"endpoints"`
	ConfigVersion   int64             `json:"config_version"`
	UpdatedAt       time.Time         `json:"updated_at"`
	UpdatedBy       int64             `json:"updated_by"`
	ChangeSummary   string            `json:"change_summary"`
}

type ActiveEndpoint struct {
	ID         string
	Name       string
	Protocol   string
	Adapter    string
	BaseURL    string
	Model      string
	AccountID  int64
	Token      string
	TimeoutMS  int
	InputLimit int
	Enabled    bool
	// TokenInvalid marks an endpoint whose persisted token ciphertext cannot be
	// decrypted with the current encryption key (key changed or auto-generated
	// on restart). The endpoint is kept visible for admins but excluded from
	// runtime use until the token is re-entered or cleared (issue #4887).
	TokenInvalid bool
}

type ActiveConfig struct {
	RiskControlEnabled          bool
	Enabled                     bool
	BlockingEnabled             bool
	BlockingAuditMode           string
	BackgroundAuditMode         string
	BlockingLatestTurnOnly      bool
	StorePassEvents             bool
	AdaptiveEnabled             bool
	AdaptiveCollectWhenDisabled bool
	AdaptiveAllowSampleRate     int
	AdaptiveRiskSampleRate      int
	OutputAuditEnabled          bool
	OutputAllowSampleRate       int
	OutputRiskSampleRate        int
	Strategy                    string
	WorkerCount                 int
	PromptChunkConcurrency      int
	QueueCapacity               int
	Scanners                    []string
	AllGroups                   bool
	GroupIDs                    []int64
	WhitelistEmails             []string
	Endpoints                   []ActiveEndpoint
	ConfigVersion               int64
	UpdatedAt                   time.Time
	UpdatedBy                   int64
	ChangeSummary               string
}

type PublicEndpoint struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Adapter     string `json:"adapter"`
	BaseURL     string `json:"base_url"`
	Model       string `json:"model"`
	AccountID   int64  `json:"account_id,omitempty"`
	TimeoutMS   int    `json:"timeout_ms"`
	InputLimit  int    `json:"input_limit"`
	Enabled     bool   `json:"enabled"`
	HasToken    bool   `json:"has_token"`
	TokenStatus string `json:"token_status"`
}

type PublicConfig struct {
	Enabled                     bool             `json:"enabled"`
	BlockingEnabled             bool             `json:"blocking_enabled"`
	BlockingAuditMode           string           `json:"blocking_audit_mode"`
	BackgroundAuditMode         string           `json:"background_audit_mode"`
	BlockingLatestTurnOnly      bool             `json:"blocking_latest_turn_only"`
	StorePassEvents             bool             `json:"store_pass_events"`
	AdaptiveEnabled             bool             `json:"adaptive_enabled"`
	AdaptiveCollectWhenDisabled bool             `json:"adaptive_collect_when_disabled"`
	AdaptiveAllowSampleRate     int              `json:"adaptive_allow_sample_rate"`
	AdaptiveRiskSampleRate      int              `json:"adaptive_risk_sample_rate"`
	OutputAuditEnabled          bool             `json:"output_audit_enabled"`
	OutputAllowSampleRate       int              `json:"output_allow_sample_rate"`
	OutputRiskSampleRate        int              `json:"output_risk_sample_rate"`
	EffectiveMode               Mode             `json:"effective_mode"`
	Strategy                    string           `json:"strategy"`
	WorkerCount                 int              `json:"worker_count"`
	PromptChunkConcurrency      int              `json:"prompt_chunk_concurrency"`
	QueueCapacity               int              `json:"queue_capacity"`
	Scanners                    []string         `json:"scanners"`
	AllGroups                   bool             `json:"all_groups"`
	GroupIDs                    []int64          `json:"group_ids"`
	WhitelistEmails             []string         `json:"whitelist_emails"`
	Endpoints                   []PublicEndpoint `json:"endpoints"`
	ConfigVersion               int64            `json:"config_version"`
	UpdatedAt                   time.Time        `json:"updated_at"`
	UpdatedBy                   int64            `json:"updated_by"`
	ChangeSummary               string           `json:"change_summary"`
}

// PromptPolicyVersion is deliberately metadata-only: config_snapshot contains
// encrypted endpoint credentials and must never be returned by the admin API.
type PromptPolicyVersion struct {
	ID            int64     `json:"id"`
	ConfigVersion int64     `json:"config_version"`
	EndpointOrder []string  `json:"endpoint_order"`
	CreatedBy     int64     `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	ChangeSummary string    `json:"change_summary"`
}

type RollbackPolicyRequest struct {
	ExpectedConfigVersion int64 `json:"expected_config_version" binding:"required"`
}

type UpdateEndpoint struct {
	ID         string `json:"id" binding:"required"`
	Name       string `json:"name" binding:"required"`
	Protocol   string `json:"protocol"`
	Adapter    string `json:"adapter"`
	BaseURL    string `json:"base_url"`
	Model      string `json:"model"`
	AccountID  int64  `json:"account_id,omitempty"`
	Token      string `json:"token,omitempty"`
	ClearToken bool   `json:"clear_token"`
	TimeoutMS  int    `json:"timeout_ms"`
	InputLimit int    `json:"input_limit"`
	Enabled    bool   `json:"enabled"`
}

type UpdateConfigRequest struct {
	ExpectedConfigVersion       int64            `json:"expected_config_version" binding:"required"`
	Enabled                     bool             `json:"enabled"`
	BlockingEnabled             bool             `json:"blocking_enabled"`
	BlockingAuditMode           string           `json:"blocking_audit_mode"`
	BackgroundAuditMode         string           `json:"background_audit_mode"`
	BlockingLatestTurnOnly      bool             `json:"blocking_latest_turn_only"`
	StorePassEvents             bool             `json:"store_pass_events"`
	AdaptiveEnabled             bool             `json:"adaptive_enabled"`
	AdaptiveCollectWhenDisabled bool             `json:"adaptive_collect_when_disabled"`
	AdaptiveAllowSampleRate     int              `json:"adaptive_allow_sample_rate"`
	AdaptiveRiskSampleRate      int              `json:"adaptive_risk_sample_rate"`
	OutputAuditEnabled          bool             `json:"output_audit_enabled"`
	OutputAllowSampleRate       int              `json:"output_allow_sample_rate"`
	OutputRiskSampleRate        int              `json:"output_risk_sample_rate"`
	Strategy                    string           `json:"strategy"`
	WorkerCount                 int              `json:"worker_count"`
	PromptChunkConcurrency      *int             `json:"prompt_chunk_concurrency"`
	QueueCapacity               int              `json:"queue_capacity"`
	Scanners                    []string         `json:"scanners"`
	AllGroups                   bool             `json:"all_groups"`
	GroupIDs                    []int64          `json:"group_ids"`
	WhitelistEmails             *[]string        `json:"whitelist_emails"`
	Endpoints                   []UpdateEndpoint `json:"endpoints"`
}

func DefaultStorageConfig() storageConfig {
	return storageConfig{
		Enabled:                     false,
		BlockingEnabled:             false,
		BlockingAuditMode:           BlockingAuditModeFull,
		BackgroundAuditMode:         BackgroundAuditModeOff,
		BlockingLatestTurnOnly:      false,
		StorePassEvents:             false,
		AdaptiveEnabled:             false,
		AdaptiveCollectWhenDisabled: true,
		AdaptiveAllowSampleRate:     DefaultAdaptiveAllowSampleRate,
		AdaptiveRiskSampleRate:      DefaultAdaptiveRiskSampleRate,
		OutputAuditEnabled:          false,
		OutputAllowSampleRate:       DefaultOutputAllowSampleRate,
		OutputRiskSampleRate:        DefaultOutputRiskSampleRate,
		Strategy:                    "priority",
		WorkerCount:                 DefaultWorkerCount,
		PromptChunkConcurrency:      DefaultPromptChunkConcurrency,
		QueueCapacity:               DefaultQueueCapacity,
		Scanners:                    append([]string(nil), AllScannerIDs...),
		AllGroups:                   true,
		GroupIDs:                    []int64{},
		WhitelistEmails:             []string{},
		Endpoints:                   []StorageEndpoint{},
		ConfigVersion:               1,
	}
}

func ParseStorageConfig(raw string) (storageConfig, error) {
	cfg := DefaultStorageConfig()
	if strings.TrimSpace(raw) == "" {
		normalizeStorageConfig(&cfg)
		return cfg, nil
	}
	rawJSON := []byte(raw)
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return storageConfig{}, fmt.Errorf("decode prompt audit config: %w", err)
	}
	// Old snapshots predate blocking_audit_mode. Clear the default so
	// normalization can infer their behavior from the legacy boolean.
	var persistedFields map[string]json.RawMessage
	if err := json.Unmarshal(rawJSON, &persistedFields); err == nil {
		_, blockingModeExists := persistedFields["blocking_audit_mode"]
		if !blockingModeExists {
			cfg.BlockingAuditMode = ""
		}
		if _, exists := persistedFields["background_audit_mode"]; !exists {
			// Preserve the administrator's old scope selection when migrating an
			// asynchronous policy. A blocking-only policy did not previously run a
			// second background audit, so it migrates to off.
			if cfg.BlockingEnabled {
				cfg.BackgroundAuditMode = BackgroundAuditModeOff
			} else {
				cfg.BackgroundAuditMode = normalizeBlockingAuditMode(cfg.BlockingAuditMode, cfg.BlockingLatestTurnOnly)
			}
		}
	}
	normalizeStorageConfig(&cfg)
	if err := validateStorageConfig(cfg); err != nil {
		return storageConfig{}, err
	}
	return cfg, nil
}

func normalizeStorageConfig(cfg *storageConfig) {
	if cfg == nil {
		return
	}
	if cfg.ConfigVersion < 1 {
		cfg.ConfigVersion = 1
	}
	cfg.BlockingAuditMode = normalizeBlockingAuditMode(cfg.BlockingAuditMode, cfg.BlockingLatestTurnOnly)
	cfg.BackgroundAuditMode = normalizeBackgroundAuditMode(cfg.BackgroundAuditMode)
	// Self-heal snapshots produced before foreground/background scopes were
	// separated. Explicit admin updates are still rejected earlier when they
	// request no gate and no background audit.
	if cfg.Enabled && !cfg.BlockingEnabled && cfg.BackgroundAuditMode == BackgroundAuditModeOff {
		cfg.BackgroundAuditMode = cfg.BlockingAuditMode
	}
	// Keep the legacy flag coherent for rollback snapshots and old clients.
	cfg.BlockingLatestTurnOnly = cfg.BlockingAuditMode != BlockingAuditModeFull
	if strings.TrimSpace(cfg.Strategy) == "" {
		cfg.Strategy = "priority"
	}
	if cfg.WorkerCount == 0 {
		cfg.WorkerCount = DefaultWorkerCount
	}
	if cfg.PromptChunkConcurrency == 0 {
		cfg.PromptChunkConcurrency = DefaultPromptChunkConcurrency
	}
	if cfg.QueueCapacity == 0 {
		cfg.QueueCapacity = DefaultQueueCapacity
	}
	if len(cfg.Scanners) == 0 {
		cfg.Scanners = append([]string(nil), AllScannerIDs...)
	}
	cfg.Scanners = canonicalScannerIDs(cfg.Scanners)
	cfg.GroupIDs = canonicalInt64s(cfg.GroupIDs)
	cfg.WhitelistEmails = canonicalWhitelistEmails(cfg.WhitelistEmails)
	// Preserve an invalid blocking-without-audit combination so validation can
	// reject it instead of silently changing administrator intent.
	for i := range cfg.Endpoints {
		ep := &cfg.Endpoints[i]
		ep.ID = strings.TrimSpace(ep.ID)
		ep.Name = strings.TrimSpace(ep.Name)
		ep.Protocol = strings.TrimSpace(ep.Protocol)
		if ep.Protocol == "" {
			ep.Protocol = EndpointProtocolOpenAICompatible
		}
		ep.Adapter = strings.TrimSpace(ep.Adapter)
		if ep.Adapter == "" {
			if isInternalEndpointProtocol(ep.Protocol) {
				ep.Adapter = EndpointAdapterGenericLLM
			} else {
				ep.Adapter = EndpointAdapterQwen3Guard
			}
		}
		ep.BaseURL = strings.TrimSpace(ep.BaseURL)
		ep.Model = strings.TrimSpace(ep.Model)
		if ep.Model == "" {
			switch ep.Protocol {
			case JevProtocol:
				ep.Model = DefaultJevModel
			case EndpointProtocolAntigravityInternal:
				ep.Model = DefaultAntigravityAuditModel
			case EndpointProtocolOpenAIInternal:
				ep.Model = DefaultOpenAIInternalAuditModel
			default:
				ep.Model = DefaultGuardModel
			}
		}
		if ep.TimeoutMS == 0 {
			ep.TimeoutMS = DefaultTimeoutMS
		}
		if ep.InputLimit == 0 {
			ep.InputLimit = DefaultInputLimit
		}
	}
}

func validateStorageConfig(cfg storageConfig) error {
	if cfg.BlockingEnabled && !cfg.Enabled {
		return infraerrors.BadRequest(ErrorCodeRequiresEnabled, "开启同步阻止前必须先启用提示词审计")
	}
	if !validBlockingAuditMode(normalizeBlockingAuditMode(cfg.BlockingAuditMode, cfg.BlockingLatestTurnOnly)) {
		return infraerrors.BadRequest("prompt_audit_invalid_blocking_audit_mode", "前置审核方式无效")
	}
	if !validBackgroundAuditMode(cfg.BackgroundAuditMode) {
		return infraerrors.BadRequest("prompt_audit_invalid_background_audit_mode", "后台审核方式无效")
	}
	if cfg.Enabled && !cfg.BlockingEnabled && cfg.BackgroundAuditMode == BackgroundAuditModeOff {
		return infraerrors.BadRequest("prompt_audit_background_required", "无门禁时必须选择后台审核范围")
	}
	if cfg.Strategy != "priority" {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 priority")
	}
	if cfg.WorkerCount < 1 || cfg.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if cfg.PromptChunkConcurrency < MinPromptChunkConcurrency || cfg.PromptChunkConcurrency > MaxPromptChunkConcurrency {
		return infraerrors.BadRequest("prompt_audit_invalid_chunk_concurrency", "单请求分块并发超出允许范围")
	}
	if cfg.QueueCapacity < 1 || cfg.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if !validSampleRate(cfg.AdaptiveAllowSampleRate) || !validSampleRate(cfg.AdaptiveRiskSampleRate) ||
		!validSampleRate(cfg.OutputAllowSampleRate) || !validSampleRate(cfg.OutputRiskSampleRate) {
		return infraerrors.BadRequest("prompt_audit_invalid_sample_rate", "审计抽样比例必须在 0 到 100 之间")
	}
	if !cfg.AllGroups && len(cfg.GroupIDs) == 0 {
		return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
	}
	if len(cfg.WhitelistEmails) > MaxPromptAuditWhitelistEmails {
		return infraerrors.BadRequest("prompt_audit_whitelist_too_large", "提示词审计白名单最多支持 500 个邮箱")
	}
	for _, email := range cfg.WhitelistEmails {
		if !validWhitelistEmail(email) {
			return infraerrors.BadRequest("prompt_audit_invalid_whitelist_email", "提示词审计白名单包含无效邮箱")
		}
	}
	if len(cfg.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	seen := make(map[string]struct{}, len(cfg.Endpoints))
	enabled := 0
	enabledProtocol := ""
	for _, ep := range cfg.Endpoints {
		if (ep.Protocol != EndpointProtocolOpenAICompatible && ep.Protocol != JevProtocol) || ep.AccountID != 0 {
			return cpapolicy.Required()
		}
		if ep.ID == "" || ep.Name == "" {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint", "审计节点 ID 和名称不能为空")
		}
		if _, ok := seen[ep.ID]; ok {
			return infraerrors.BadRequest("prompt_audit_duplicate_endpoint", "审计节点 ID 不能重复")
		}
		seen[ep.ID] = struct{}{}
		switch ep.Protocol {
		case JevProtocol:
			if err := validateJevOptions(ep.BaseURL, ep.Model, ep.TimeoutMS, ep.InputLimit); err != nil {
				return infraerrors.BadRequest("prompt_audit_invalid_jev_endpoint", err.Error())
			}
			if ep.Enabled && strings.TrimSpace(ep.TokenCiphertext) == "" {
				return infraerrors.BadRequest("prompt_audit_jev_token_required", "启用 Jev 前必须配置凭据")
			}
		case EndpointProtocolOpenAICompatible:
			if ep.AccountID != 0 {
				return infraerrors.BadRequest("prompt_audit_invalid_account", "只有 OpenAI 内部审计节点可以指定 OAuth 账号")
			}
			if _, err := NormalizeBaseURL(ep.BaseURL); err != nil {
				return err
			}
			model := strings.ToLower(strings.TrimSpace(ep.Model))
			validOpenCodeModel := model == "deepseek-v4-flash" || model == "deepseek-v4.1-flash"
			if isOpenCodeAuditBaseURL(ep.BaseURL) && (ep.ID != "deepseek-fallback" || ep.Adapter != EndpointAdapterGenericLLM || !validOpenCodeModel) {
				return infraerrors.BadRequest("prompt_audit_invalid_endpoint", "OpenCode 仅允许作为 DeepSeek V4 Flash 或 V4.1 Flash 审计兜底节点")
			}
		case EndpointProtocolAntigravityInternal:
			if ep.AccountID != 0 {
				return infraerrors.BadRequest("prompt_audit_invalid_account", "只有 OpenAI 内部审计节点可以指定 OAuth 账号")
			}
			if ep.Adapter != EndpointAdapterGenericLLM || !strings.HasPrefix(ep.Model, "gemini-") {
				return infraerrors.BadRequest("prompt_audit_invalid_endpoint", "Antigravity 内部审计节点必须使用 Gemini 通用分类器")
			}
		case EndpointProtocolOpenAIInternal:
			if ep.AccountID < 0 {
				return infraerrors.BadRequest("prompt_audit_invalid_account", "OpenAI OAuth 账号 ID 无效")
			}
			if ep.Adapter != EndpointAdapterGenericLLM || !strings.HasPrefix(ep.Model, "gpt-") {
				return infraerrors.BadRequest("prompt_audit_invalid_endpoint", "OpenAI 内部审计节点必须使用 GPT 通用分类器")
			}
		default:
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_protocol", "审计节点协议无效")
		}
		if ep.Adapter != EndpointAdapterQwen3Guard && ep.Adapter != EndpointAdapterGenericLLM {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_adapter", "审计节点输出适配器无效")
		}
		if ep.TimeoutMS < MinTimeoutMS || ep.TimeoutMS > MaxTimeoutMS {
			return infraerrors.BadRequest("prompt_audit_invalid_timeout", "审计节点超时超出允许范围")
		}
		if ep.InputLimit < MinInputLimit || ep.InputLimit > MaxInputLimit {
			return infraerrors.BadRequest("prompt_audit_invalid_input_limit", "审计节点输入上限超出允许范围")
		}
		if ep.Enabled {
			if enabledProtocol != "" && enabledProtocol != ep.Protocol {
				return infraerrors.BadRequest("prompt_audit_mixed_provider_pool", "同一审查池不能同时启用 Jev 与 Qwen；切换时停用旧节点，避免隐式跨服务商降级")
			}
			enabledProtocol = ep.Protocol
			enabled++
		}
	}
	if cfg.Enabled && enabled == 0 {
		return infraerrors.BadRequest("prompt_audit_endpoint_required", "启用提示词审计前至少需要启用一个审计节点")
	}
	return nil
}

func validateUpdateConfigRequest(req UpdateConfigRequest) error {
	if mode := normalizeBlockingAuditMode(req.BlockingAuditMode, req.BlockingLatestTurnOnly); !validBlockingAuditMode(mode) {
		return infraerrors.BadRequest("prompt_audit_invalid_blocking_audit_mode", "前置审核方式无效")
	}
	backgroundMode := requestedBackgroundAuditMode(req)
	if !validBackgroundAuditMode(backgroundMode) {
		return infraerrors.BadRequest("prompt_audit_invalid_background_audit_mode", "后台审核方式无效")
	}
	if req.Enabled && !req.BlockingEnabled && backgroundMode == BackgroundAuditModeOff {
		return infraerrors.BadRequest("prompt_audit_background_required", "无门禁时必须选择后台审核范围")
	}
	if strings.TrimSpace(req.Strategy) != "priority" {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 priority")
	}
	if req.WorkerCount < 1 || req.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if req.PromptChunkConcurrency != nil && (*req.PromptChunkConcurrency < MinPromptChunkConcurrency || *req.PromptChunkConcurrency > MaxPromptChunkConcurrency) {
		return infraerrors.BadRequest("prompt_audit_invalid_chunk_concurrency", "单请求分块并发超出允许范围")
	}
	if req.QueueCapacity < 1 || req.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if !validSampleRate(req.AdaptiveAllowSampleRate) || !validSampleRate(req.AdaptiveRiskSampleRate) ||
		!validSampleRate(req.OutputAllowSampleRate) || !validSampleRate(req.OutputRiskSampleRate) {
		return infraerrors.BadRequest("prompt_audit_invalid_sample_rate", "审计抽样比例必须在 0 到 100 之间")
	}
	if len(req.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	for _, scanner := range req.Scanners {
		if _, ok := ScannerCatalog[NormalizeCategory(scanner)]; !ok {
			return infraerrors.BadRequest("prompt_audit_invalid_scanner", "提示词审计风险分类无效")
		}
	}
	if !req.AllGroups {
		if len(req.GroupIDs) == 0 {
			return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
		}
		for _, groupID := range req.GroupIDs {
			if groupID <= 0 {
				return infraerrors.BadRequest("prompt_audit_invalid_group", "提示词审计分组 ID 无效")
			}
		}
	}
	for _, endpoint := range req.Endpoints {
		if (endpoint.Protocol != "" && endpoint.Protocol != EndpointProtocolOpenAICompatible && endpoint.Protocol != JevProtocol) || endpoint.AccountID != 0 {
			return cpapolicy.Required()
		}
		if _, err := normalizeAuditEndpointURL(endpoint.Protocol, endpoint.BaseURL); err != nil {
			return err
		}
		if endpoint.AccountID < 0 || (endpoint.AccountID != 0 && endpoint.Protocol != EndpointProtocolOpenAIInternal) {
			return infraerrors.BadRequest("prompt_audit_invalid_account", "OpenAI OAuth 账号 ID 无效")
		}
		if endpoint.TimeoutMS < MinTimeoutMS || endpoint.TimeoutMS > MaxTimeoutMS {
			return infraerrors.BadRequest("prompt_audit_invalid_timeout", "审计节点超时超出允许范围")
		}
		if endpoint.InputLimit < MinInputLimit || endpoint.InputLimit > MaxInputLimit {
			return infraerrors.BadRequest("prompt_audit_invalid_input_limit", "审计节点输入上限超出允许范围")
		}
	}
	return nil
}

func validSampleRate(value int) bool { return value >= 0 && value <= 100 }

func validWhitelistEmail(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 254 || strings.Count(value, "@") != 1 || strings.ContainsAny(value, " \t\r\n*?[]") {
		return false
	}
	parts := strings.SplitN(value, "@", 2)
	return parts[0] != "" && strings.Contains(parts[1], ".") && !strings.HasPrefix(parts[1], ".") && !strings.HasSuffix(parts[1], ".")
}

func normalizeBlockingAuditMode(mode string, legacyLatestTurnOnly bool) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "" {
		return mode
	}
	if legacyLatestTurnOnly {
		return BlockingAuditModeIncrementalFull
	}
	return BlockingAuditModeFull
}

func validBlockingAuditMode(mode string) bool {
	switch mode {
	case BlockingAuditModeFastLatest, BlockingAuditModeIncrementalFull, BlockingAuditModeFull:
		return true
	default:
		return false
	}
}

func normalizeBackgroundAuditMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return BackgroundAuditModeOff
	}
	return mode
}

// requestedBackgroundAuditMode keeps pre-background-mode admin clients
// compatible. An omitted field inherits their existing audit scope; an
// explicit "off" still means off and is rejected when there is no gate.
func requestedBackgroundAuditMode(req UpdateConfigRequest) string {
	if strings.TrimSpace(req.BackgroundAuditMode) == "" && req.Enabled && !req.BlockingEnabled {
		return normalizeBlockingAuditMode(req.BlockingAuditMode, req.BlockingLatestTurnOnly)
	}
	return normalizeBackgroundAuditMode(req.BackgroundAuditMode)
}

func validBackgroundAuditMode(mode string) bool {
	if mode == BackgroundAuditModeOff {
		return true
	}
	return validBlockingAuditMode(mode)
}

func (cfg ActiveConfig) EffectiveBlockingAuditMode() string {
	return normalizeBlockingAuditMode(cfg.BlockingAuditMode, cfg.BlockingLatestTurnOnly)
}

func (cfg ActiveConfig) EffectiveBackgroundAuditMode() string {
	if strings.TrimSpace(cfg.BackgroundAuditMode) == "" && cfg.Enabled && !cfg.BlockingEnabled {
		return cfg.EffectiveBlockingAuditMode()
	}
	return normalizeBackgroundAuditMode(cfg.BackgroundAuditMode)
}

func (cfg ActiveConfig) EffectiveMode() Mode {
	if !cfg.RiskControlEnabled || !cfg.Enabled {
		return ModeOff
	}
	if cfg.BlockingEnabled {
		return ModeBlocking
	}
	return ModeAsync
}

func (cfg ActiveConfig) IncludesGroup(groupID *int64) bool {
	if cfg.AllGroups {
		return true
	}
	if groupID == nil {
		return false
	}
	i := sort.Search(len(cfg.GroupIDs), func(i int) bool { return cfg.GroupIDs[i] >= *groupID })
	return i < len(cfg.GroupIDs) && cfg.GroupIDs[i] == *groupID
}

func (cfg ActiveConfig) IncludesWhitelistEmail(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	i := sort.SearchStrings(cfg.WhitelistEmails, email)
	return i < len(cfg.WhitelistEmails) && cfg.WhitelistEmails[i] == email
}

func (cfg ActiveConfig) EnabledEndpoints() []ActiveEndpoint {
	result := make([]ActiveEndpoint, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		if ep.Enabled {
			result = append(result, ep)
		}
	}
	return result
}

// InvalidTokenEndpointIDs lists endpoints whose stored token could not be
// decrypted with the current encryption key.
func (cfg ActiveConfig) InvalidTokenEndpointIDs() []string {
	ids := make([]string, 0)
	for _, ep := range cfg.Endpoints {
		if ep.TokenInvalid {
			ids = append(ids, ep.ID)
		}
	}
	return ids
}

func PublicFromStorage(cfg storageConfig, riskControlEnabled bool, invalidTokenEndpointIDs []string) PublicConfig {
	invalid := make(map[string]struct{}, len(invalidTokenEndpointIDs))
	for _, id := range invalidTokenEndpointIDs {
		invalid[id] = struct{}{}
	}
	scanners := append([]string{}, cfg.Scanners...)
	groupIDs := append([]int64{}, cfg.GroupIDs...)
	whitelistEmails := append([]string{}, cfg.WhitelistEmails...)
	endpoints := make([]PublicEndpoint, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		hasToken := strings.TrimSpace(ep.TokenCiphertext) != ""
		status := "missing"
		if isInternalEndpointProtocol(ep.Protocol) {
			status = "not_required"
		} else if hasToken {
			status = "configured"
			if _, ok := invalid[ep.ID]; ok {
				status = "invalid"
			}
		}
		endpoints = append(endpoints, PublicEndpoint{
			ID: ep.ID, Name: ep.Name, Protocol: ep.Protocol, Adapter: ep.Adapter, BaseURL: ep.BaseURL,
			Model: ep.Model, AccountID: ep.AccountID, TimeoutMS: ep.TimeoutMS, InputLimit: ep.InputLimit,
			Enabled: ep.Enabled, HasToken: hasToken, TokenStatus: status,
		})
	}
	active := ActiveConfig{
		RiskControlEnabled:  riskControlEnabled,
		Enabled:             cfg.Enabled,
		BlockingEnabled:     cfg.BlockingEnabled,
		BlockingAuditMode:   cfg.BlockingAuditMode,
		BackgroundAuditMode: cfg.BackgroundAuditMode,
	}
	return PublicConfig{
		Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled, BlockingAuditMode: cfg.BlockingAuditMode,
		BackgroundAuditMode:    cfg.BackgroundAuditMode,
		BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly, StorePassEvents: cfg.StorePassEvents,
		AdaptiveEnabled: cfg.AdaptiveEnabled, AdaptiveCollectWhenDisabled: cfg.AdaptiveCollectWhenDisabled,
		AdaptiveAllowSampleRate: cfg.AdaptiveAllowSampleRate, AdaptiveRiskSampleRate: cfg.AdaptiveRiskSampleRate,
		OutputAuditEnabled: cfg.OutputAuditEnabled, OutputAllowSampleRate: cfg.OutputAllowSampleRate, OutputRiskSampleRate: cfg.OutputRiskSampleRate,
		EffectiveMode: active.EffectiveMode(), Strategy: cfg.Strategy, WorkerCount: cfg.WorkerCount,
		PromptChunkConcurrency: cfg.PromptChunkConcurrency,
		QueueCapacity:          cfg.QueueCapacity, Scanners: scanners, AllGroups: cfg.AllGroups,
		GroupIDs: groupIDs, WhitelistEmails: whitelistEmails, Endpoints: endpoints, ConfigVersion: cfg.ConfigVersion,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
	}
}

func ActiveFromStorage(cfg storageConfig, riskControlEnabled bool, encryptor SecretEncryptor) (ActiveConfig, error) {
	active := ActiveConfig{
		RiskControlEnabled: riskControlEnabled, Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled,
		BlockingAuditMode: cfg.BlockingAuditMode, BackgroundAuditMode: cfg.BackgroundAuditMode, BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly,
		StorePassEvents: cfg.StorePassEvents, Strategy: cfg.Strategy, WorkerCount: cfg.WorkerCount,
		AdaptiveEnabled: cfg.AdaptiveEnabled, AdaptiveCollectWhenDisabled: cfg.AdaptiveCollectWhenDisabled,
		AdaptiveAllowSampleRate: cfg.AdaptiveAllowSampleRate, AdaptiveRiskSampleRate: cfg.AdaptiveRiskSampleRate,
		OutputAuditEnabled: cfg.OutputAuditEnabled, OutputAllowSampleRate: cfg.OutputAllowSampleRate, OutputRiskSampleRate: cfg.OutputRiskSampleRate,
		PromptChunkConcurrency: cfg.PromptChunkConcurrency,
		QueueCapacity:          cfg.QueueCapacity, Scanners: append([]string(nil), cfg.Scanners...), AllGroups: cfg.AllGroups,
		GroupIDs: append([]int64(nil), cfg.GroupIDs...), WhitelistEmails: append([]string(nil), cfg.WhitelistEmails...), ConfigVersion: cfg.ConfigVersion,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
		Endpoints: make([]ActiveEndpoint, 0, len(cfg.Endpoints)),
	}
	for _, ep := range cfg.Endpoints {
		token := ""
		tokenInvalid := false
		if !isInternalEndpointProtocol(ep.Protocol) && ep.TokenCiphertext != "" {
			if encryptor == nil {
				return ActiveConfig{}, fmt.Errorf("prompt audit secret encryptor unavailable")
			}
			plain, err := encryptor.Decrypt(ep.TokenCiphertext)
			if err != nil {
				// An undecryptable token (encryption key changed or regenerated)
				// must not take the whole config down: admins would otherwise be
				// locked out of the real config version and unable to recover
				// (issue #4887). Keep the ciphertext persisted, but exclude the
				// endpoint from runtime use until the token is re-entered.
				tokenInvalid = true
			} else {
				token = plain
			}
		}
		active.Endpoints = append(active.Endpoints, ActiveEndpoint{
			ID: ep.ID, Name: ep.Name, Protocol: ep.Protocol, Adapter: ep.Adapter, BaseURL: ep.BaseURL, Model: ep.Model,
			AccountID: ep.AccountID,
			Token:     token, TimeoutMS: ep.TimeoutMS, InputLimit: ep.InputLimit,
			Enabled: ep.Enabled && !tokenInvalid, TokenInvalid: tokenInvalid,
		})
	}
	return active, nil
}

func changeSummary(cfg storageConfig) string {
	summary := struct {
		Enabled                bool   `json:"enabled"`
		BlockingEnabled        bool   `json:"blocking_enabled"`
		BlockingAuditMode      string `json:"blocking_audit_mode"`
		BackgroundAuditMode    string `json:"background_audit_mode"`
		BlockingLatestTurnOnly bool   `json:"blocking_latest_turn_only"`
		StorePassEvents        bool   `json:"store_pass_events"`
		AdaptiveEnabled        bool   `json:"adaptive_enabled"`
		OutputAuditEnabled     bool   `json:"output_audit_enabled"`
		PromptChunkConcurrency int    `json:"prompt_chunk_concurrency"`
		EndpointCount          int    `json:"endpoint_count"`
		ScannerCount           int    `json:"scanner_count"`
		AllGroups              bool   `json:"all_groups"`
		GroupCount             int    `json:"group_count"`
		GroupHash              string `json:"group_hash"`
		WhitelistCount         int    `json:"whitelist_count"`
		WhitelistHash          string `json:"whitelist_hash"`
	}{cfg.Enabled, cfg.BlockingEnabled, cfg.BlockingAuditMode, cfg.BackgroundAuditMode, cfg.BlockingLatestTurnOnly, cfg.StorePassEvents, cfg.AdaptiveEnabled, cfg.OutputAuditEnabled, cfg.PromptChunkConcurrency, len(cfg.Endpoints), len(cfg.Scanners), cfg.AllGroups, len(cfg.GroupIDs), "", len(cfg.WhitelistEmails), ""}
	rawGroups, _ := json.Marshal(cfg.GroupIDs)
	digest := sha256.Sum256(rawGroups)
	summary.GroupHash = hex.EncodeToString(digest[:])
	rawWhitelist, _ := json.Marshal(cfg.WhitelistEmails)
	whitelistDigest := sha256.Sum256(rawWhitelist)
	summary.WhitelistHash = hex.EncodeToString(whitelistDigest[:])
	raw, _ := json.Marshal(summary)
	return string(raw)
}

func canonicalInt64s(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func canonicalWhitelistEmails(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		email := strings.ToLower(strings.TrimSpace(value))
		if email == "" {
			continue
		}
		if _, ok := seen[email]; ok {
			continue
		}
		seen[email] = struct{}{}
		result = append(result, email)
	}
	sort.Strings(result)
	return result
}

func canonicalScannerIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		id := NormalizeCategory(value)
		if _, ok := ScannerCatalog[id]; ok {
			seen[id] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for _, id := range AllScannerIDs {
		if _, ok := seen[id]; ok {
			result = append(result, id)
		}
	}
	return result
}
