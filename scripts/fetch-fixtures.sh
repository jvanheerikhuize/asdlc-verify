#!/usr/bin/env bash
# Fetches the pinned spec tag's gate policy and golden conformance bundles
# from jvanheerikhuize/asdlc into testdata/spec-pinned/. The pinned tag is
# read from spec.pin at the repo root.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="$(tr -d ' \t\n' < "$repo_root/spec.pin")"
dest="$repo_root/testdata/spec-pinned"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git clone --quiet --depth 1 --branch "$tag" \
    https://github.com/jvanheerikhuize/asdlc.git "$work/asdlc"

rm -rf "$dest"
mkdir -p "$dest/gates" "$dest/golden"
cp "$work/asdlc/spec/gates/g4-merge.rego" "$dest/gates/g4-merge.rego"
cp -r "$work/asdlc/spec/examples/golden/." "$dest/golden/"

echo "fetched spec fixtures at $tag into $dest"
