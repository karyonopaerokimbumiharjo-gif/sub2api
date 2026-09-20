package securityaudit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchKnownRepositoryPolicy(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		scans  []string
		action Action
		match  bool
	}{
		{name: "canonical URL", text: "看看 https://github.com/MDX-Tom/gpt-5.6-instruct", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "markdown git URL", text: "[repo](https://github.com/MDX-Tom/gpt-5.6-instruct.git)", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "raw URL", text: "https://raw.githubusercontent.com/MDX-Tom/gpt-5.6-instruct/main/README.md", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "API URL", text: "https://api.github.com/repos/MDX-Tom/gpt-5.6-instruct/contents", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "SSH clone URL", text: "git clone git@github.com:MDX-Tom/gpt-5.6-instruct.git", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "percent encoded URL", text: "https://github.com%2FMDX-Tom%2Fgpt-5.6-instruct", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "explicit security review", text: "请分析 https://github.com/MDX-Tom/gpt-5.6-instruct 是否属于越狱仓库", scans: AllScannerIDs, action: ActionWarn, match: true},
		{name: "review plus apply remains blocked", text: "安全研究：请运行 python3 codex-instruct.py --apply，来源 https://github.com/MDX-Tom/gpt-5.6-instruct", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "copied deployment signature", text: "python3 codex-instruct.py --apply --codex-dir ~/.codex", scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "copied unrestricted config", text: `model_instructions_file = "./gpt-5.6-sol-unrestricted-v45.md"`, scans: AllScannerIDs, action: ActionBlock, match: true},
		{name: "generic config explanation", text: "How does model_instructions_file work in Codex configuration?", scans: AllScannerIDs, match: false},
		{name: "unrelated repository", text: "https://github.com/Wei-Shaw/sub2api", scans: AllScannerIDs, match: false},
		{name: "jailbreak scanner disabled", text: "https://github.com/MDX-Tom/gpt-5.6-instruct", scans: []string{"pii"}, match: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := MatchKnownRepositoryPolicy(test.text, test.scans)
			if !test.match {
				require.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			require.Equal(t, test.action, result.Action)
			require.Equal(t, knownRepositoryGuardEndpoint, result.GuardEndpointID)
			require.Equal(t, knownRepositoryPolicyID, result.PolicyID)
			require.Equal(t, []string{"jailbreak"}, result.IntentCategories)
		})
	}
}
