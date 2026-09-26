package auditpolicy

type BioPolicy struct {
	Tier        string `json:"tier"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

var BioTiers = []BioPolicy{
	{"B0", "Benign biology, public health, provenance, citation, safety and non-operational research", "allow"},
	{"B1", "General dual-use concepts; high-level explanation without operational capability uplift", "allow_limited"},
	{"B2", "Concrete operational capability uplift with materially unclear intent or authorization", "review_required"},
	{"B3", "Actionable assistance materially enabling harmful biological or chemical activity", "block"},
	{"B4", "Real-world acquisition, weaponization, deployment, target selection or execution of biological or chemical harm", "hard_block"},
}
