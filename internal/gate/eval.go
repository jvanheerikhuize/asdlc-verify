// Package gate evaluates a spec gate policy over a prepared evidence input.
// It is a pure function of (policy, input): no platform calls, no file I/O.
package gate

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

type Result struct {
	Gate  string   `json:"gate"`
	Allow bool     `json:"allow"`
	Deny  []string `json:"deny"`
}

// Evaluate runs the gate's Rego policy against the input and returns the
// verdict. The policy package must be data.asdlc.gates.<gate, lowercased>.
func Evaluate(ctx context.Context, gateName, policySrc string, input any) (Result, error) {
	res := Result{Gate: gateName, Deny: []string{}}
	query := "data.asdlc.gates." + strings.ToLower(gateName)
	r := rego.New(
		rego.Query(query),
		rego.Module(strings.ToLower(gateName)+".rego", policySrc),
		rego.Input(input),
	)
	rs, err := r.Eval(ctx)
	if err != nil {
		return res, fmt.Errorf("policy evaluation: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return res, fmt.Errorf("policy produced no result for %s", query)
	}
	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return res, fmt.Errorf("unexpected policy result shape %T", rs[0].Expressions[0].Value)
	}
	if allow, ok := doc["allow"].(bool); ok {
		res.Allow = allow
	}
	if denySet, ok := doc["deny"].([]any); ok {
		for _, d := range denySet {
			if s, ok := d.(string); ok {
				res.Deny = append(res.Deny, s)
			}
		}
	}
	sort.Strings(res.Deny)
	// Defense in depth: never report allow with standing deny reasons, even
	// if a future policy's allow rule is buggy.
	if len(res.Deny) > 0 {
		res.Allow = false
	}
	return res, nil
}
