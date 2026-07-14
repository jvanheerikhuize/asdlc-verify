// asdlc-verify — the ASDLC enforcement point. Small and dumb by design:
// validate evidence, resolve authority, evaluate the gate policy, report.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jvanheerikhuize/asdlc-verify/internal/bundle"
	"github.com/jvanheerikhuize/asdlc-verify/internal/gate"
	"github.com/jvanheerikhuize/asdlc-verify/internal/manifest"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gate":
		os.Exit(runGate(os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  asdlc-verify gate -gate G4 -spec <spec-dir> [-input <prepared.json> | -change-dir <dir> -head <sha> -manifest <asdlc.yaml> -dev-unsigned]
  asdlc-verify doctor -manifest <asdlc.yaml>`)
}

func runGate(args []string) int {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	gateName := fs.String("gate", "G4", "gate to evaluate (e.g. G4)")
	specDir := fs.String("spec", "", "path to the pinned spec content (required)")
	inputPath := fs.String("input", "", "prepared policy input (conformance mode)")
	changeDir := fs.String("change-dir", "", "Change Record directory (.asdlc/changes/<id>)")
	head := fs.String("head", "", "head commit sha the gate is evaluated against")
	manifestPath := fs.String("manifest", "asdlc.yaml", "consuming repo manifest")
	devUnsigned := fs.Bool("dev-unsigned", false, "trust-on-read mode: skip signature verification (NON-ENFORCING)")
	fs.Parse(args)

	if *specDir == "" {
		fmt.Fprintln(os.Stderr, "error: -spec is required")
		return 2
	}
	policyPath := filepath.Join(*specDir, "gates", strings.ToLower(*gateName)+"-merge.rego")
	policySrc, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read gate policy: %v\n", err)
		return 2
	}

	var in *bundle.Input
	switch {
	case *inputPath != "":
		in, err = bundle.LoadPrepared(*inputPath)
	case *changeDir != "":
		if *head == "" {
			fmt.Fprintln(os.Stderr, "error: -head is required with -change-dir")
			return 2
		}
		var m *manifest.Manifest
		m, err = manifest.Load(*manifestPath)
		if err != nil {
			break
		}
		if *devUnsigned {
			fmt.Fprintln(os.Stderr, "WARNING: --dev-unsigned — signatures NOT verified; this run is not enforcement-grade evidence")
		}
		in, err = bundle.Build(*changeDir, filepath.Join(*specDir, "controls", "catalogue.yaml"), *head, m, *devUnsigned)
	default:
		fmt.Fprintln(os.Stderr, "error: one of -input or -change-dir is required")
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	res, err := gate.Evaluate(context.Background(), *gateName, string(policySrc), in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if !res.Allow {
		return 1
	}
	return 0
}

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	manifestPath := fs.String("manifest", "asdlc.yaml", "consuming repo manifest")
	fs.Parse(args)

	m, err := manifest.Load(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
		return 1
	}
	fmt.Printf("spec_version: %s\n", m.SpecVersion)
	fmt.Printf("roles bound: %d\n", len(m.RoleBindings))
	if id, solo := m.SoDException(); solo {
		fmt.Printf("NOTE: standing separation-of-duty exception — %s holds every role (recorded, not hidden)\n", id)
	}
	fmt.Println("ok")
	return 0
}
