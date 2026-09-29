package auditpolicy

const NativeProfileEnhanced = "enhanced"
const NativeProfileUpstream = "upstream"

// Optional additions to the original profile are independent of the saved
// enhanced selection. Old configurations therefore remain the original 13.
func NormalizeUpstreamExtensions(ids []string) []string {
	out := []string{}
	for _, id := range []string{"biological_risk", "operator_ctf", "operator_repository"} {
		if HasCategory(ids, id) {
			out = append(out, id)
		}
	}
	return out
}

func ValidUpstreamExtensions(ids []string) bool {
	for _, id := range ids {
		if id != "biological_risk" && id != "operator_ctf" && id != "operator_repository" {
			return false
		}
	}
	return true
}

func UpstreamCategories(extensions []string) []string {
	return append(ContentCategoryIDs(), NormalizeUpstreamExtensions(extensions)...)
}

func ValidNativeProfile(profile string) bool {
	return profile == "" || profile == NativeProfileEnhanced || profile == NativeProfileUpstream
}

func NormalizeNativeProfile(profile string) string {
	if profile == NativeProfileUpstream {
		return NativeProfileUpstream
	}
	return NativeProfileEnhanced
}

// NativeRiskCatalog is the administrator checklist. Broad legacy duplicates
// are deliberately absent; the original detailed content categories remain.
type RiskCategory struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	LabelEN     string `json:"label_en"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

var NativeRiskCatalog = []RiskCategory{
	{"harassment", "骚扰", "Harassment", "content", "辱骂、贬损或骚扰；中立报道与反骚扰引用除外。"},
	{"harassment/threatening", "威胁性骚扰", "Threatening harassment", "content", "骚扰中包含可信的人身伤害或严重暴力威胁。"},
	{"hate", "仇恨", "Hate", "content", "基于受保护身份煽动仇恨或贬低群体。"},
	{"hate/threatening", "威胁性仇恨", "Threatening hate", "content", "基于受保护身份威胁或煽动暴力。"},
	{"illicit", "违法行为", "Illicit activity", "content", "实施违法行为的可操作帮助；包含原非暴力违法行为分类。"},
	{"illicit/violent", "暴力违法行为", "Violent illicit activity", "content", "实施暴力违法行为的可操作帮助。"},
	{"self-harm", "自伤内容", "Self-harm", "content", "宣扬、鼓励或描写自我伤害；预防与康复支持除外。"},
	{"self-harm/intent", "自伤意图", "Self-harm intent", "content", "正在实施或打算实施自杀、自残等行为的意图。"},
	{"self-harm/instructions", "自伤方法或指导", "Self-harm instructions", "content", "实施自伤的具体方法或指导。"},
	{"sexual", "性内容", "Sexual content", "content", "露骨性内容；临床医学与性教育除外。"},
	{"sexual/minors", "涉及未成年人的性内容", "Sexual content involving minors", "content", "涉及未成年人的性化描写或性行为。"},
	{"violence", "暴力", "Violence", "content", "描写、鼓励或威胁身体伤害；包含原暴力意图分类。"},
	{"violence/graphic", "血腥暴力", "Graphic violence", "content", "露骨的血腥或重伤细节。"},
	{"biological_risk", "生物与化学风险（B0–B4）", "Biological and chemical risk (B0–B4)", "intent", "B0 普通知识；B1 限制放行并检查输出；B2 待复核；B3/B4 拦截。"},
	{"pii", "隐私与凭据泄露", "Privacy and credential abuse", "intent", "未经授权披露、收集或窃取隐私或凭据；不因普通联系方式单独拦截。"},
	{"unethical_acts", "欺骗、胁迫与剥削", "Deception, coercion and exploitation", "intent", "针对他人的欺骗、胁迫或剥削行为；不等于普通观点分歧。"},
	{"politically_sensitive_topics", "政治恐吓、打压与监控", "Political intimidation and surveillance", "intent", "政治恐吓、打压参与或监控；普通新闻、讨论与批评不在此列。"},
	{"copyright_violation", "版权侵权", "Copyright infringement", "intent", "未经授权的大量复制受保护作品；摘要、公共领域与用户材料转换除外。"},
	{"jailbreak", "越狱与提示注入", "Jailbreak and prompt injection", "intent", "实际尝试覆盖可信指令、关闭安全检查或提取隐藏信息。"},
	{"operator_ctf", "CTF 全局拦截", "CTF global rule", "operator", "平台单独禁止的 CTF 相关内容；不受普通分组范围和审核开关影响。"},
	{"operator_repository", "破甲库全局拦截（539项）", "Jailbreak repository global rule (539)", "operator", "已收录仓库、别名与素材特征，包含引用和分析；与一般提示注入意图区分。"},
}

func HasCategory(ids []string, id string) bool {
	for _, value := range ids {
		if value == id {
			return true
		}
	}
	return false
}
func CloneCategories(ids []string) []string {
	if ids == nil {
		return nil
	}
	return append([]string{}, ids...)
}

// Missing new selection migrates the old always-on 13 categories and only
// the six complementary intent categories. An explicit empty list stays empty.
func ResolveNativeCategories(selected, legacyScanners []string, operatorEnabled bool) []string {
	out := []string{}
	for _, c := range NativeRiskCatalog {
		enabled := HasCategory(selected, c.ID)
		if selected == nil {
			enabled = c.Kind == "content" || c.Kind == "intent" && HasCategory(legacyScanners, c.ID) || c.Kind == "operator" && operatorEnabled
		}
		if c.Kind == "operator" && !operatorEnabled {
			enabled = false
		}
		if enabled {
			out = append(out, c.ID)
		}
	}
	return out
}

func ValidNativeCategories(ids []string) bool {
	for _, id := range ids {
		known := false
		for _, c := range NativeRiskCatalog {
			if c.ID == id {
				known = true
				break
			}
		}
		if !known {
			return false
		}
	}
	return true
}

func HasOperatorCategory(ids []string) bool {
	return HasCategory(ids, "operator_ctf") || HasCategory(ids, "operator_repository")
}
func ContentCategoryIDs() []string {
	out := []string{}
	for _, c := range NativeRiskCatalog {
		if c.Kind == "content" {
			out = append(out, c.ID)
		}
	}
	return out
}
