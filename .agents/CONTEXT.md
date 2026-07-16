# Repository Context

<!-- Maintained by RSI audit system. Local agents: update this when you change architecture. -->
<!-- Last updated: 2026-07-16 by RSI audit (bootstrap) -->

## Tech Stack
- Primary: go, shell
- Build: go
- CI: github-actions

## Architecture
The enforcement point of the [ASDLC framework](https://github.com/jvanheerikhuize/asdlc): a small, dumb Go CLI that validates a Change Record's evidence bundle against the pinned spec and evaluates the gate policy. Runs as a required check in the GitHub reference binding; runs identically in any CI.

### Entry Points
- `cmd/asdlc-verify/main.go`
