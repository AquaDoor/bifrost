package aquadoorpii

// In-process RU PII recognizer + anonymizer (Bifrost unified gateway, #1780 §7.5).
//
// This REPLACES the former out-of-process Microsoft Presidio dependency (a separate Python +
// spaCy image the plugin used to HTTP-call). The load-bearing 152-ФЗ identifiers — INN, OGRN,
// OGRNIP (checksum-validated), RU phone, RU passport — are pure regex + checksum, so they belong
// compiled INTO the fork: no separate service to deploy or keep alive, no swarm RAM cost, and
// FAIL-CLOSED BY CONSTRUCTION — there is no network hop that can time out and fail open (the
// class of bug §7.5 warned about). The recognizer runs in-process on every PreLLMHook, cannot be
// "unavailable", and never egresses the prompt to detect PII in it.
//
// Faithful port of the retired infra/presidio-ru logic (ru_checksums.py + ru_recognizers.py):
//   - INN/OGRN/OGRNIP: regex matches the SHAPE, the checksum decides real-vs-false-positive.
//   - Phone/passport: no checksum → regex + a REQUIRED context word nearby (Presidio's context
//     enhancement, made a hard gate here) so a bare 10-digit order number is not mistaken for a
//     passport. The +7/8 phone shape is distinctive enough to detect without context too.
//
// Residual (unchanged from the spec): unstructured PII that only NER catches (person names,
// addresses) is NOT detected here — the spec documents this as an accepted recall gap, mitigated
// by these high-confidence recognizers + monitoring, not eliminated. A RU-resident NER backend
// (its own capacity decision, like the RU-LLM GPU gate) can be added later without changing this
// contract.

import (
	"regexp"
	"strconv"
	"strings"
)

// AnalyzerResult is one detected entity span (byte offsets into the analyzed text). Kept as the
// recognizer's output shape; the PreLLMHook consumes EntityType (block-vs-redact) + offsets.
type AnalyzerResult struct {
	EntityType string
	Start      int
	End        int
	Score      float64
}

// Entity type identifiers. INN is split by length because the two carry DIFFERENT legal status
// under 152-ФЗ (О персональных данных): a 10-digit INN + a 13-digit OGRN identify a LEGAL ENTITY
// (public business-registry data — NOT personal data), whereas a 12-digit INN, a 15-digit OGRNIP,
// a passport and a phone identify an INDIVIDUAL (personal data). AquaDoor is a B2B tender/dealer
// platform, so legal-entity identifiers are the legitimate PAYLOAD of tender/dealer analysis and
// must NOT be masked; individual identifiers are personal data and are redacted before off-shore
// egress. The per-type action policy (main.go Actions) encodes this, config-overridable.
const (
	entityINNLegal = "RU_INN_LEGAL" // 10-digit, legal entity → business data (allow by default)
	entityINN      = "RU_INN"       // 12-digit, individual → personal data (redact)
	entityOGRN     = "RU_OGRN"      // 13-digit, legal entity → business data (allow)
	entityOGRNIP   = "RU_OGRNIP"    // 15-digit, individual entrepreneur → personal-ish (redact)
	entityPhone    = "RU_PHONE"
	entityPassport = "RU_PASSPORT"
)

// contextWindow is how many bytes on either side of a match are scanned for a context word when a
// recognizer is context-gated (phone/passport). Matches Presidio's default context window scale.
const contextWindow = 60

var (
	// A digit run of exactly 10 or 12 (INN) — \b delimits the run so a sub-run of a longer number
	// is not matched. RE2 \b treats non-ASCII (Cyrillic) as a boundary, which only ever widens
	// detection (fail-closed direction).
	reINN      = regexp.MustCompile(`\b(\d{10}|\d{12})\b`)
	reOGRN     = regexp.MustCompile(`\b\d{13}\b`)
	reOGRNIP   = regexp.MustCompile(`\b\d{15}\b`)
	rePhone    = regexp.MustCompile(`(?:\+7|7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}`)
	rePassport = regexp.MustCompile(`\b\d{2}\s?\d{2}\s?\d{6}\b|\b\d{2}\s?\d{7}\b`)

	innContext      = []string{"инн", "inn", "налогоплательщик", "налог"}
	ogrnContext     = []string{"огрн", "ogrn", "регистрационный"}
	ogrnipContext   = []string{"огрнип", "ogrnip", "предприниматель", "ип"}
	passportContext = []string{"паспорт", "серия", "passport", "документ"}
)

// digitsOnly strips spaces/hyphens so a checksum runs on the raw digit string (a matched INN never
// carries separators, but phone/passport do; kept general).
func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}

// validateINN — ИНН, 10-digit (legal entity) or 12-digit (individual/ИП), weighted mod-11 (10→0).
func validateINN(inn string) bool {
	if !allDigits(inn) {
		return false
	}
	d := toDigits(inn)
	switch len(d) {
	case 10:
		w := []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
		n := weightedMod11(w, d, 9)
		return n == d[9]
	case 12:
		w11 := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		w12 := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		n1 := weightedMod11(w11, d, 10)
		n2 := weightedMod11(w12, d, 11)
		return n1 == d[10] && n2 == d[11]
	default:
		return false
	}
}

// validateOGRN — ОГРН, 13 digits; control = (first 12 as int) mod 11, младший разряд (10→0).
func validateOGRN(ogrn string) bool {
	if !allDigits(ogrn) || len(ogrn) != 13 {
		return false
	}
	head, err := strconv.ParseInt(ogrn[:12], 10, 64)
	if err != nil {
		return false
	}
	rem := head % 11 % 10
	return int(rem) == int(ogrn[12]-'0')
}

// validateOGRNIP — ОГРНИП, 15 digits; control = (first 14 as int) mod 13, младший разряд (>9 → −10).
func validateOGRNIP(ogrnip string) bool {
	if !allDigits(ogrnip) || len(ogrnip) != 15 {
		return false
	}
	head, err := strconv.ParseInt(ogrnip[:14], 10, 64)
	if err != nil {
		return false
	}
	rem := head % 13 % 10 // rem∈[0,12]; %10 maps 10,11,12 → 0,1,2 (matches the Python port)
	return int(rem) == int(ogrnip[14]-'0')
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func toDigits(s string) []int {
	d := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		d[i] = int(s[i] - '0')
	}
	return d
}

// weightedMod11 = (Σ w[i]*d[i] for i in [0,n)) % 11 % 10 — the %10 collapses the 10→0 rule.
func weightedMod11(w, d []int, n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		sum += w[i] * d[i]
	}
	return sum % 11 % 10
}

// recognize scans text and returns non-overlapping detected entities (byte offsets into text),
// filtered to `entities` when that set is non-empty. Deterministic + allocation-light; no I/O.
func recognize(text string, entities []string) []AnalyzerResult {
	want := func(t string) bool {
		if len(entities) == 0 {
			return true
		}
		for _, e := range entities {
			if e == t {
				return true
			}
		}
		return false
	}
	lower := strings.ToLower(text)
	var out []AnalyzerResult

	// Checksum-gated identifiers — the checksum IS the gate (no context needed; a valid checksum is
	// high-confidence). INN before OGRNIP before OGRN is irrelevant (distinct lengths); overlap
	// resolution below dedupes the INN-vs-passport 10-digit collision in passport's favor only when
	// the INN checksum fails.
	// INN — checksum-validated, then tagged by length: 10-digit = legal entity, 12-digit = individual.
	for _, m := range reINN.FindAllStringIndex(text, -1) {
		match := text[m[0]:m[1]]
		if !validateINN(match) {
			continue
		}
		et := entityINN // 12-digit individual
		if len(match) == 10 {
			et = entityINNLegal
		}
		if want(et) {
			out = append(out, AnalyzerResult{EntityType: et, Start: m[0], End: m[1], Score: 1.0})
		}
	}
	if want(entityOGRN) {
		for _, m := range reOGRN.FindAllStringIndex(text, -1) {
			if validateOGRN(text[m[0]:m[1]]) {
				out = append(out, AnalyzerResult{EntityType: entityOGRN, Start: m[0], End: m[1], Score: 1.0})
			}
		}
	}
	if want(entityOGRNIP) {
		for _, m := range reOGRNIP.FindAllStringIndex(text, -1) {
			if validateOGRNIP(text[m[0]:m[1]]) {
				out = append(out, AnalyzerResult{EntityType: entityOGRNIP, Start: m[0], End: m[1], Score: 1.0})
			}
		}
	}
	// Phone — distinctive +7/8 shape; detected on pattern (no context gate needed).
	if want(entityPhone) {
		for _, m := range rePhone.FindAllStringIndex(text, -1) {
			out = append(out, AnalyzerResult{EntityType: entityPhone, Start: m[0], End: m[1], Score: 0.6})
		}
	}
	// Passport — no checksum, and its 10-digit shape collides with any bare number, so it is
	// CONTEXT-GATED (redact only when a passport context word sits nearby). Prevents redacting every
	// order/invoice number as a passport.
	if want(entityPassport) {
		for _, m := range rePassport.FindAllStringIndex(text, -1) {
			if hasContextNear(lower, m[0], m[1], passportContext) {
				out = append(out, AnalyzerResult{EntityType: entityPassport, Start: m[0], End: m[1], Score: 0.6})
			}
		}
	}

	return resolveOverlaps(out)
}

// hasContextNear reports whether any context word appears within contextWindow bytes of [start,end)
// in the already-lowercased haystack.
func hasContextNear(lowerText string, start, end int, ctxWords []string) bool {
	from := start - contextWindow
	if from < 0 {
		from = 0
	}
	to := end + contextWindow
	if to > len(lowerText) {
		to = len(lowerText)
	}
	window := lowerText[from:to]
	for _, w := range ctxWords {
		if strings.Contains(window, w) {
			return true
		}
	}
	return false
}

// resolveOverlaps keeps the highest-score result per overlapping region (ties → the earlier/longer
// one), so a span is redacted exactly once and a checksum-validated INN wins over a passport shape
// on the same digits.
func resolveOverlaps(in []AnalyzerResult) []AnalyzerResult {
	if len(in) < 2 {
		return in
	}
	// Sort by score desc, then by span length desc, then by start asc — a stable priority order.
	sorted := make([]AnalyzerResult, len(in))
	copy(sorted, in)
	sortResults(sorted)
	var kept []AnalyzerResult
	for _, r := range sorted {
		overlap := false
		for _, k := range kept {
			if r.Start < k.End && k.Start < r.End {
				overlap = true
				break
			}
		}
		if !overlap {
			kept = append(kept, r)
		}
	}
	return kept
}

func sortResults(rs []AnalyzerResult) {
	// insertion sort — result sets are tiny; avoids importing sort for a hot, small slice.
	for i := 1; i < len(rs); i++ {
		j := i
		for j > 0 && lessPriority(rs[j], rs[j-1]) {
			rs[j], rs[j-1] = rs[j-1], rs[j]
			j--
		}
	}
}

// lessPriority: higher score first; then longer span; then earlier start.
func lessPriority(a, b AnalyzerResult) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	la, lb := a.End-a.Start, b.End-b.Start
	if la != lb {
		return la > lb
	}
	return a.Start < b.Start
}

// anonymize replaces each detected span with a <TYPE> placeholder (Presidio's default operator),
// applied right-to-left so earlier byte offsets stay valid. Non-overlapping input (resolveOverlaps)
// guarantees clean replacement.
func anonymize(text string, results []AnalyzerResult) string {
	if len(results) == 0 {
		return text
	}
	ordered := make([]AnalyzerResult, len(results))
	copy(ordered, results)
	// sort by Start descending
	for i := 1; i < len(ordered); i++ {
		j := i
		for j > 0 && ordered[j].Start > ordered[j-1].Start {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
			j--
		}
	}
	out := text
	for _, r := range ordered {
		if r.Start < 0 || r.End > len(out) || r.Start >= r.End {
			continue
		}
		out = out[:r.Start] + "<" + r.EntityType + ">" + out[r.End:]
	}
	return out
}
