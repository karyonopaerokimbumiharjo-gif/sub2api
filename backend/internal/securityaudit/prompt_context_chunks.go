package securityaudit

// Native Jev chunks retain a bounded excerpt of the request's opening context.
// This helps distinguish quoted research data from an instruction to carry out
// the behavior described in that data. The excerpt remains untrusted evidence.
func splitPromptAuditChunks(text string, limit int, endpoints []ActiveEndpoint) []string {
	for _, ep := range endpoints {
		if ep.Protocol != JevProtocol {
			return SplitRunes(text, limit)
		}
	}
	runes := []rune(text)
	if len(endpoints) == 0 || limit < 1024 || len(runes) <= limit {
		return SplitRunes(text, limit)
	}
	const contextSize = 512
	const separator = "\n[End of repeated untrusted request context; next contiguous content chunk follows]\n"
	prefix := string(runes[:contextSize]) + separator
	payloadLimit := limit - len([]rune(prefix))
	chunks := []string{string(runes[:limit])}
	for offset := limit; offset < len(runes); offset += payloadLimit {
		end := offset + payloadLimit
		if end > len(runes) {
			end = len(runes)
		}
		chunks = append(chunks, prefix+string(runes[offset:end]))
	}
	return chunks
}
