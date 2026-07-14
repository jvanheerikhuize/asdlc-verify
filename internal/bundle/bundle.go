// Package bundle assembles the gate-policy input from a Change Record
// directory and the pinned spec content.
//
// v0.1 signature posture: statements are plain JSON files and only the
// --dev-unsigned mode exists, which marks every statement
// signature_verified=true, takes the signer identity from the statement's
// own produced_by claim, and resolves roles via the manifest. That is
// trust-on-read and is loudly flagged; DSSE/Sigstore verification replaces
// it before the gate can be called enforcing. The input SHAPE is final —
// the policy contract does not change when real verification lands.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jvanheerikhuize/asdlc-verify/internal/manifest"
	"gopkg.in/yaml.v3"
)

type Signer struct {
	Identity string   `json:"identity"`
	Roles    []string `json:"roles"`
}

type Meta struct {
	SHA256            string `json:"sha256"`
	SignatureVerified bool   `json:"signature_verified"`
	Signer            Signer `json:"signer"`
}

type StatementEntry struct {
	Meta      Meta           `json:"meta"`
	Statement map[string]any `json:"statement"`
}

type Input struct {
	Change     map[string]any   `json:"change"`
	Head       map[string]any   `json:"head"`
	Catalogue  map[string]any   `json:"catalogue"`
	Statements []StatementEntry `json:"statements"`
}

// LoadPrepared reads an already-assembled policy input (conformance mode:
// the spec's golden bundles are in this shape).
func LoadPrepared(path string) (*Input, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &in, nil
}

// Build assembles the policy input from a change directory
// (change.json + evidence/*.json), the spec's control catalogue, the head
// commit, and the manifest for role resolution. devUnsigned must be true in
// v0.1 (see package comment).
func Build(changeDir, cataloguePath, headCommit string, m *manifest.Manifest, devUnsigned bool) (*Input, error) {
	if !devUnsigned {
		return nil, fmt.Errorf("signature verification is not implemented yet; v0.1 requires --dev-unsigned (trust-on-read, non-enforcing)")
	}

	change, err := readJSON(filepath.Join(changeDir, "change.json"))
	if err != nil {
		return nil, err
	}

	catalogue, err := readYAML(cataloguePath)
	if err != nil {
		return nil, err
	}

	evidenceDir := filepath.Join(changeDir, "evidence")
	files, err := filepath.Glob(filepath.Join(evidenceDir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	in := &Input{
		Change:     change,
		Head:       map[string]any{"gitCommit": headCommit},
		Catalogue:  catalogue,
		Statements: []StatementEntry{},
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var st map[string]any
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		digest := sha256.Sum256(raw)
		identity := claimedIdentity(st)
		in.Statements = append(in.Statements, StatementEntry{
			Meta: Meta{
				SHA256:            hex.EncodeToString(digest[:]),
				SignatureVerified: true, // dev-unsigned: trust-on-read, flagged by caller
				Signer:            Signer{Identity: identity, Roles: m.RolesFor(identity)},
			},
			Statement: st,
		})
	}
	return in, nil
}

func claimedIdentity(statement map[string]any) string {
	pred, _ := statement["predicate"].(map[string]any)
	pb, _ := pred["produced_by"].(map[string]any)
	id, _ := pb["identity"].(string)
	return id
}

func readJSON(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return v, nil
}

func readYAML(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return v, nil
}
