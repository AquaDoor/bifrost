package mcp

import "testing"

// #1780 §7.4 — bare-name bijection + fail-closed ambiguity guard (mirrors the CF fork).

func TestPartitionBareToolNames_NoCollision(t *testing.T) {
	in := []PrefixedTool{
		{PrefixedName: "aquadoor-runner-tender-tender_lead", ClientName: "aquadoor-runner-tender"},
		{PrefixedName: "aquadoor-runner-catalog-catalog_export_series", ClientName: "aquadoor-runner-catalog"},
	}
	bareOk, ambiguous := PartitionBareToolNames(in)
	if len(ambiguous) != 0 {
		t.Fatalf("expected no ambiguous, got %v", ambiguous)
	}
	if len(bareOk) != 2 {
		t.Fatalf("expected 2 bare tools, got %d", len(bareOk))
	}
	// bare names are the client-prefix-stripped originals, and they round-trip to the prefixed form.
	m := BareToPrefixed(bareOk)
	if m["tender_lead"] != "aquadoor-runner-tender-tender_lead" {
		t.Errorf("tender_lead -> %q", m["tender_lead"])
	}
	if m["catalog_export_series"] != "aquadoor-runner-catalog-catalog_export_series" {
		t.Errorf("catalog_export_series -> %q", m["catalog_export_series"])
	}
	// an agent binds the bare name; it resolves to exactly one exec name.
	exec, found := ResolveBareToExecName(m, "tender_lead")
	if !found || exec != "aquadoor-runner-tender-tender_lead" {
		t.Errorf("resolve tender_lead: found=%v exec=%q", found, exec)
	}
}

func TestPartitionBareToolNames_AmbiguousExcluded(t *testing.T) {
	// same bare tool (`search`) federated via two clients → ambiguous → excluded, fail-closed.
	in := []PrefixedTool{
		{PrefixedName: "clientA-search", ClientName: "clientA"},
		{PrefixedName: "clientB-search", ClientName: "clientB"},
		{PrefixedName: "clientA-unique_tool", ClientName: "clientA"},
	}
	bareOk, ambiguous := PartitionBareToolNames(in)
	if len(ambiguous) != 1 || ambiguous[0] != "search" {
		t.Fatalf("expected ambiguous=[search], got %v", ambiguous)
	}
	// only the unique tool is servable bare
	if len(bareOk) != 1 || bareOk[0].BareName != "unique_tool" {
		t.Fatalf("expected bareOk=[unique_tool], got %+v", bareOk)
	}
	// the ambiguous bare name is NOT resolvable → caller refuses (never guesses a client)
	m := BareToPrefixed(bareOk)
	if _, found := ResolveBareToExecName(m, "search"); found {
		t.Error("ambiguous 'search' must NOT resolve (fail-closed)")
	}
}

func TestResolveBareToExecName_UnknownPassesThrough(t *testing.T) {
	m := BareToPrefixed([]BareTool{{BareName: "a", PrefixedName: "c-a"}})
	// an already-prefixed / native name is unknown to the bare map → found=false (pass through).
	if _, found := ResolveBareToExecName(m, "some-native-name"); found {
		t.Error("unknown name should not be found in the bare map")
	}
}
