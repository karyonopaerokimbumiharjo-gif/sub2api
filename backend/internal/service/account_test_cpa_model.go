package service

import "sort"

// Default CPA tests must avoid retired upstream models and stay within any
// explicitly configured account whitelist.
func defaultCPAAccountTestModel(account *Account) string {
	const preferred = "gpt-6-astra"
	mapping := account.GetModelMapping()
	if len(mapping) == 0 || account.IsOpenAIPassthroughEnabled() {
		return preferred
	}
	if account.IsModelSupported(preferred) {
		return preferred
	}
	models := make([]string, 0, len(mapping))
	for model := range mapping {
		models = append(models, model)
	}
	sort.Strings(models)
	return models[0]
}
