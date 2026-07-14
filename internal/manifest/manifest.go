// Package manifest reads the consuming repo's asdlc.yaml and resolves
// identities to authority-matrix roles.
package manifest

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	SpecVersion  string              `yaml:"spec_version"`
	RoleBindings map[string][]string `yaml:"role_bindings"`
}

func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.SpecVersion == "" {
		return nil, fmt.Errorf("%s: spec_version is required", path)
	}
	if len(m.RoleBindings) == 0 {
		return nil, fmt.Errorf("%s: role_bindings is required and non-empty", path)
	}
	return &m, nil
}

// RolesFor returns the roles an identity is bound to, sorted.
func (m *Manifest) RolesFor(identity string) []string {
	var roles []string
	for role, ids := range m.RoleBindings {
		for _, id := range ids {
			if id == identity {
				roles = append(roles, role)
				break
			}
		}
	}
	sort.Strings(roles)
	return roles
}

// SoDException reports whether a single identity holds every bound role —
// the solo-maintainer case. It is recorded, never hidden.
func (m *Manifest) SoDException() (string, bool) {
	counts := map[string]int{}
	for _, ids := range m.RoleBindings {
		seen := map[string]bool{}
		for _, id := range ids {
			if !seen[id] {
				counts[id]++
				seen[id] = true
			}
		}
	}
	for id, n := range counts {
		if n == len(m.RoleBindings) {
			return id, true
		}
	}
	return "", false
}
