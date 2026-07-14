package gate_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jvanheerikhuize/asdlc-verify/internal/bundle"
	"github.com/jvanheerikhuize/asdlc-verify/internal/gate"
)

// Conformance: the verifier must reproduce, bundle for bundle, the outcomes
// the spec's golden fixtures pin. Fixtures are a pinned copy of
// asdlc-spec 0.1.0 (testdata/spec-0.1.0); replace with a tag fetch once spec
// releases are tagged.
func TestG4GoldenConformance(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "spec-0.1.0")
	policySrc, err := os.ReadFile(filepath.Join(root, "gates", "g4-merge.rego"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}

	bundles, err := filepath.Glob(filepath.Join(root, "golden", "*"))
	if err != nil || len(bundles) == 0 {
		t.Fatalf("no golden bundles found: %v", err)
	}

	for _, dir := range bundles {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			in, err := bundle.LoadPrepared(filepath.Join(dir, "input.json"))
			if err != nil {
				t.Fatalf("load input: %v", err)
			}
			var expected struct {
				Allow           bool     `json:"allow"`
				DenyMustInclude []string `json:"deny_must_include"`
			}
			raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err != nil {
				t.Fatalf("load expected: %v", err)
			}
			if err := json.Unmarshal(raw, &expected); err != nil {
				t.Fatalf("parse expected: %v", err)
			}

			res, err := gate.Evaluate(context.Background(), "G4", string(policySrc), in)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Allow != expected.Allow {
				t.Errorf("allow = %v, expected %v (deny: %v)", res.Allow, expected.Allow, res.Deny)
			}
			for _, must := range expected.DenyMustInclude {
				if !slices.Contains(res.Deny, must) {
					t.Errorf("deny missing %q; got %v", must, res.Deny)
				}
			}
			if expected.Allow && len(res.Deny) != 0 {
				t.Errorf("passing bundle has deny reasons: %v", res.Deny)
			}
		})
	}
}
