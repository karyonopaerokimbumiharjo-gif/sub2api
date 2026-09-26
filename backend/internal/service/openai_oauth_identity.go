package service

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Workspace IDs identify a ChatGPT organization, not its individual members.
// Tokens have already been authorized before reaching this identity projection.
func openAIOAuthIdentityClaims(credentials map[string]any) []map[string]any {
	var result []map[string]any
	for _, field := range []string{"access_token", "id_token"} {
		parts := strings.Split(openAICPACredentialString(credentials, field), ".")
		if len(parts) != 3 || len(parts[1]) > 1<<20 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
		if err != nil {
			continue
		}
		var claims map[string]any
		if json.Unmarshal(raw, &claims) == nil && claims != nil {
			result = append(result, claims)
		}
	}
	return result
}

func OpenAIOAuthPrincipal(credentials map[string]any) string {
	claims := openAIOAuthIdentityClaims(credentials)
	for _, claim := range claims {
		if auth, ok := claim["https://api.openai.com/auth"].(map[string]any); ok {
			for _, key := range []string{"chatgpt_user_id", "user_id"} {
				if id := strings.TrimSpace(openAICPACredentialString(auth, key)); id != "" {
					return "user:" + id
				}
			}
		}
	}
	for _, claim := range claims {
		if id := strings.TrimSpace(openAICPACredentialString(claim, "sub")); id != "" {
			return "user:" + id
		}
	}
	if id := strings.TrimSpace(openAICPACredentialString(credentials, "chatgpt_user_id")); id != "" {
		return "user:" + id
	}
	if id := strings.TrimSpace(openAICPACredentialString(credentials, "openai_oauth_principal")); id != "" {
		return id
	}
	if email := openAIOAuthEmail(credentials); email != "" {
		return "email:" + email
	}
	return ""
}

func openAIOAuthEmail(credentials map[string]any) string {
	for _, claim := range openAIOAuthIdentityClaims(credentials) {
		if profile, ok := claim["https://api.openai.com/profile"].(map[string]any); ok {
			if email := strings.TrimSpace(openAICPACredentialString(profile, "email")); email != "" {
				return strings.ToLower(email)
			}
		}
		if email := strings.TrimSpace(openAICPACredentialString(claim, "email")); email != "" {
			return strings.ToLower(email)
		}
	}
	return strings.ToLower(strings.TrimSpace(openAICPACredentialString(credentials, "email")))
}

func openAIOAuthWorkspace(credentials map[string]any) string {
	for _, key := range []string{"chatgpt_account_id", "account_id"} {
		if id := strings.TrimSpace(openAICPACredentialString(credentials, key)); id != "" {
			return id
		}
	}
	return ""
}

func SameOpenAIOAuthIdentity(left, right map[string]any) bool {
	workspace := openAIOAuthWorkspace(left)
	if workspace == "" || workspace != openAIOAuthWorkspace(right) {
		return false
	}
	l, r := OpenAIOAuthPrincipal(left), OpenAIOAuthPrincipal(right)
	if l != "" && l == r {
		return true
	}
	// Old aliases retained email but not the provider's user ID. Only bridge
	// that legacy representation when both sides identify the same email.
	if strings.HasPrefix(l, "user:") && strings.HasPrefix(r, "user:") {
		return false
	}
	email := openAIOAuthEmail(left)
	return email != "" && email == openAIOAuthEmail(right)
}
