package manifest

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "asdlc.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoleResolutionAndSoD(t *testing.T) {
	m, err := Load(write(t, `
spec_version: 0.1.0
role_bindings:
  intent-owner: ["github:solo"]
  implementer: ["github:solo"]
  security-reviewer: ["github:solo"]
`))
	if err != nil {
		t.Fatal(err)
	}
	roles := m.RolesFor("github:solo")
	if !slices.Equal(roles, []string{"implementer", "intent-owner", "security-reviewer"}) {
		t.Errorf("roles = %v", roles)
	}
	if id, solo := m.SoDException(); !solo || id != "github:solo" {
		t.Errorf("SoD exception = %q, %v; expected github:solo, true", id, solo)
	}

	m2, err := Load(write(t, `
spec_version: 0.1.0
role_bindings:
  intent-owner: ["github:alice"]
  security-reviewer: ["github:bob"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, solo := m2.SoDException(); solo {
		t.Error("no SoD exception expected with separated roles")
	}
	if roles := m2.RolesFor("github:nobody"); len(roles) != 0 {
		t.Errorf("unbound identity got roles %v", roles)
	}
}

func TestLoadRejectsIncomplete(t *testing.T) {
	if _, err := Load(write(t, `role_bindings: {intent-owner: ["github:x"]}`)); err == nil {
		t.Error("missing spec_version accepted")
	}
	if _, err := Load(write(t, `spec_version: 0.1.0`)); err == nil {
		t.Error("missing role_bindings accepted")
	}
}
