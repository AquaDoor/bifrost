package mcp

import (
	"sort"

	"github.com/maximhq/bifrost/core/schemas"
)

// AquaDoor bare-name serving (Bifrost unified gateway, #1780 §7.4).
//
// Bifrost advertises federated MCP tools to the model under a CLIENT-PREFIXED name
// (`fmt.Sprintf("%s-%s", clientName, tool)`, see clientmanager.go). An archetype agent must bind
// the runner's OWN tool name (e.g. `tender_lead`), not the federation-implementation-detail name
// `aquadoor-runner-tender_lead` — the exact problem the ContextForge fork solved by serving each
// tool under its BARE `original_name`. These helpers reproduce CF's `partition_compound_bare_names`
// bijection + fail-closed ambiguity guard, keyed off the existing `stripClientPrefix`.
//
// Invariant: a bare name resolves to EXACTLY ONE prefixed tool, or is refused — never a
// silently-wrong dispatch. A bare name claimed by >=2 clients is EXCLUDED from the advertised set
// (never offered) and its execution is refused (fail-closed).

// PrefixedTool is a federated tool as Bifrost holds it: the advertised prefixed name + its client.
type PrefixedTool struct {
	PrefixedName string
	ClientName   string
}

// BareTool pairs the bare (agent-facing) name with the unique prefixed name it routes to.
type BareTool struct {
	BareName     string
	PrefixedName string
	ClientName   string
}

// PartitionBareToolNames re-keys a federated tool set to bare names for the per-user surface.
// Returns the servable-bare tools (bare name unique across clients, sorted by bare name) and the
// sorted list of ambiguous bare names that were EXCLUDED (claimed by >=2 clients — fail-closed).
func PartitionBareToolNames(prefixed []PrefixedTool) (bareOk []BareTool, ambiguous []string) {
	byBare := make(map[string][]BareTool)
	for _, t := range prefixed {
		bare := stripClientPrefix(t.PrefixedName, t.ClientName)
		byBare[bare] = append(byBare[bare], BareTool{
			BareName:     bare,
			PrefixedName: t.PrefixedName,
			ClientName:   t.ClientName,
		})
	}
	for bare, group := range byBare {
		if len(group) == 1 {
			bareOk = append(bareOk, group[0])
		} else {
			ambiguous = append(ambiguous, bare)
		}
	}
	sort.Slice(bareOk, func(i, j int) bool { return bareOk[i].BareName < bareOk[j].BareName })
	sort.Strings(ambiguous)
	return bareOk, ambiguous
}

// BareToPrefixed builds the execution-routing map: bare name -> unique prefixed name. Ambiguous
// bare names are absent (their execution is refused, not guessed).
func BareToPrefixed(bareOk []BareTool) map[string]string {
	m := make(map[string]string, len(bareOk))
	for _, t := range bareOk {
		m[t.BareName] = t.PrefixedName
	}
	return m
}

// ResolveBareToExecName translates an incoming (bare) tool-call name to the prefixed name Bifrost
// routes on. found=false means the name is unknown to the bare map (pass through unchanged — it
// may already be a prefixed/native name). An ambiguous bare name is never in the map, so it
// resolves found=false and the caller must refuse it (fail-closed) rather than execute a guess.
func ResolveBareToExecName(bareMap map[string]string, name string) (execName string, found bool) {
	p, ok := bareMap[name]
	return p, ok
}

// collectPrefixedTools flattens a GetToolPerClient result into the PrefixedTool set the bijection
// consumes. It is the single source of the federated (client-prefixed) tool universe, used by both
// the advertise path (GetAvailableTools) and the execute path (executeToolWithHooks) so the two
// stay consistent.
func collectPrefixedTools(perClient map[string][]schemas.ChatTool) []PrefixedTool {
	var out []PrefixedTool
	for clientName, tools := range perClient {
		for _, t := range tools {
			if t.Function != nil && t.Function.Name != "" {
				out = append(out, PrefixedTool{PrefixedName: t.Function.Name, ClientName: clientName})
			}
		}
	}
	return out
}

// setRequestToolName rewrites the tool-call name on a BifrostMCPRequest (the writable dual of
// GetToolName). The request is built per tools/call, so mutating its *string name field is safe
// (no shared cache). Used on the execute path to swap a bare name for its unique prefixed exec name.
func setRequestToolName(r *schemas.BifrostMCPRequest, name string) {
	if r.ChatAssistantMessageToolCall != nil && r.ChatAssistantMessageToolCall.Function.Name != nil {
		*r.ChatAssistantMessageToolCall.Function.Name = name
	}
	if r.ResponsesToolMessage != nil && r.ResponsesToolMessage.Name != nil {
		*r.ResponsesToolMessage.Name = name
	}
}
