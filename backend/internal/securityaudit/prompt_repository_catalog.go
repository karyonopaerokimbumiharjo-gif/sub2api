package securityaudit

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

//go:embed operator_denied_repositories.json
var deniedRepositoryCatalogJSON []byte

type deniedRepositoryEntry struct {
	FullName    string `json:"full_name"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

var deniedRepositoryEntries, deniedRepositoryPattern = loadDeniedRepositoryCatalog()

func loadDeniedRepositoryCatalog() ([]deniedRepositoryEntry, *regexp.Regexp) {
	var catalog struct {
		Version      int                     `json:"version"`
		Repositories []deniedRepositoryEntry `json:"repositories"`
	}
	if err := json.Unmarshal(deniedRepositoryCatalogJSON, &catalog); err != nil {
		panic(err)
	}
	if catalog.Version != 1 || len(catalog.Repositories) == 0 {
		panic("operator repository catalog is empty or invalid")
	}
	names := make([]string, 0, len(catalog.Repositories))
	seen := make(map[string]bool)
	for _, entry := range catalog.Repositories {
		name := strings.ToLower(entry.FullName)
		if strings.Count(name, "/") != 1 || seen[name] || strings.ContainsAny(name, "\r\n\t ") {
			panic("invalid or duplicate operator repository name")
		}
		seen[name] = true
		names = append(names, regexp.QuoteMeta(name))
	}
	pattern := `(?i)(?:^|[^a-z0-9_.-])(?:` + strings.Join(names, "|") + `)(?:\.git)?(?:$|[^a-z0-9_.-]|\.+(?:$|[^a-z0-9_.-]))`
	return catalog.Repositories, regexp.MustCompile(pattern)
}

var deniedRepositoryFamilyPattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_.-])(?:nerv-break-[0-9.]+|autodan(?:-turbo)?|gptfuzz(?:er)?|renellm|drattack|figstep|chatgpt[_-]dan|l1b3rt4s|l1b3rt45|jailbreak_llms|llm-jailbreaks|promptjailbreakmanual|super-instruct-codex-[0-9.]+|[0-9.]+-jailbreak-nerv-codex-instruct-[0-9.]+)(?:$|[^a-z0-9_.-]|\.+(?:$|[^a-z0-9_.-]))`)
var repositoryPathPattern = regexp.MustCompile(`(?i)(?:github\.com/|raw\.githubusercontent\.com/|codeload\.github\.com/|github\.com:|jsdelivr\.net/gh/)[a-z0-9_.-]+/([a-z0-9_.-]+)`)

func matchedDeniedRepositoryReference(text string) string {
	if match := deniedRepositoryPattern.FindString(text); match != "" {
		return strings.TrimSpace(match)
	}
	if match := deniedRepositoryFamilyPattern.FindString(text); match != "" {
		return strings.TrimSpace(match)
	}
	// Recognize newly named repositories whose names explicitly describe GPT
	// jailbreaks. Generic model names or a bare word DAN never suffice.
	for _, match := range repositoryPathPattern.FindAllStringSubmatch(text, -1) {
		name := strings.ToLower(match[1])
		model := strings.Contains(name, "gpt") || strings.Contains(name, "codex") || strings.Contains(name, "llm")
		bypass := strings.Contains(name, "jailbreak") || strings.Contains(name, "unrestricted")
		defensive := strings.Contains(name, "detect") || strings.Contains(name, "defen") || strings.Contains(name, "firewall") || strings.Contains(name, "guard") || strings.Contains(name, "shield")
		if model && bypass && !defensive {
			return match[0]
		}
	}
	return ""
}
