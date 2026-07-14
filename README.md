# asdlc-verify

The enforcement point of the [ASDLC framework](https://github.com/jvanheerikhuize/asdlc):
a small, dumb Go CLI that validates a Change Record's evidence bundle against
the pinned spec and evaluates the gate policy. Runs as a required check in the
GitHub reference binding; runs identically in any CI.

```
asdlc-verify gate -gate G4 -spec <spec-dir> \
    -change-dir .asdlc/changes/CR-... -head <sha> -manifest asdlc.yaml -dev-unsigned
asdlc-verify gate -gate G4 -spec <spec-dir> -input prepared-input.json   # conformance mode
asdlc-verify doctor -manifest asdlc.yaml
```

Exit codes: `0` gate passes · `1` gate denies (reasons on stdout as JSON) ·
`2` operational error.

## v0.1 honesty notes

- **`--dev-unsigned` is the only evidence mode**: statements are read as plain
  JSON, `signature_verified` is set on trust, and signer roles are resolved
  from the manifest's `role_bindings` against the statement's *claimed*
  identity. Loudly warned, non-enforcing. DSSE + Sigstore verification is the
  next milestone; the policy input shape is already final, so the gate
  contract does not change when it lands.
- **`testdata/spec-0.1.0/`** is a pinned copy of the spec's gate policy and
  golden bundles (conformance fixtures). Replace with a tag fetch when spec
  releases are tagged.

## Design boundaries (from the spec repo's decisions)

- Never talks to a platform; a pure function of (spec, evidence, manifest).
- Never decides anything the spec's policy doesn't — no gate logic in Go.
- The separation-of-duty exception (one identity holding every role) is
  *recorded* by `doctor`, never hidden and never a hard failure.
