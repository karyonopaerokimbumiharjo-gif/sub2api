package securityaudit

import "strings"

// RequireJevSafety is configured independently of model/product selection.
func (s *PromptService) RequireJevSafety() bool {
	if s == nil || s.config == nil {
		return false
	}
	cfg, ok := s.config.Active()
	return ok && cfg.Enabled && cfg.BlockingEnabled && cfg.JevSafetyEnabled
}

func (s *PromptService) JevBlockingReady() bool {
	if s == nil || s.config == nil || s.config.BlockingActivationDegraded() || s.EffectiveMode() != ModeBlocking {
		return false
	}
	cfg, ok := s.config.Active()
	if !ok || cfg.EffectiveMode() != ModeBlocking {
		return false
	}
	return jevEndpointsReady(cfg)
}

func jevEndpointsReady(cfg ActiveConfig) bool {
	endpoints := cfg.EnabledEndpointsFor(true)
	if len(endpoints) == 0 {
		return false
	}
	for _, endpoint := range endpoints {
		if endpoint.Protocol != JevProtocol || endpoint.TokenInvalid || strings.TrimSpace(endpoint.Token) == "" {
			return false
		}
	}
	return true
}
