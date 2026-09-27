package auditpolicy

import "testing"

func TestNativeCatalogContains13OriginalAnd8Custom(t *testing.T) {
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, c := range NativeRiskCatalog {
		if seen[c.ID] {
			t.Fatalf("duplicate category %s", c.ID)
		}
		seen[c.ID] = true
		counts[c.Kind]++
	}
	if len(seen) != 21 || counts["content"] != 13 || counts["intent"] != 6 || counts["operator"] != 2 {
		t.Fatalf("wrong counts: %v", counts)
	}
	for _, id := range []string{"violent", "non_violent_illegal_acts", "sexual_content_or_sexual_acts", "suicide_and_self_harm"} {
		if seen[id] {
			t.Fatalf("legacy duplicate still present: %s", id)
		}
	}
}

func TestNativeSelectionMigrationAndExplicitEmpty(t *testing.T) {
	legacy := []string{"violent", "non_violent_illegal_acts", "sexual_content_or_sexual_acts", "suicide_and_self_harm", "biological_risk", "pii", "unethical_acts", "politically_sensitive_topics", "copyright_violation", "jailbreak"}
	all := ResolveNativeCategories(nil, legacy, true)
	if len(all) != 21 {
		t.Fatalf("lost coverage during migration: %v", all)
	}
	if selected := ResolveNativeCategories([]string{"pii", "pii", "operator_ctf"}, legacy, false); len(selected) != 1 || selected[0] != "pii" {
		t.Fatalf("selection broadened: %v", selected)
	}
	if selected := ResolveNativeCategories([]string{}, legacy, true); selected == nil || len(selected) != 0 {
		t.Fatalf("empty selection replaced by defaults: %v", selected)
	}
	if ValidNativeCategories([]string{"unknown"}) {
		t.Fatal("accepted an unknown category")
	}
}
