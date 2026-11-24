#!/usr/bin/env bash
# Download the report artifact of one workflow run into a results folder.
# Usage: bash analysis/fetch_run.sh <run-id> <artifact-pattern> <destination>
#   e.g. bash analysis/fetch_run.sh 123456 'reports-F-*' results/detection/F/vulnerable
set -euo pipefail
id="$1"; pattern="$2"; dest="$3"
tmp=$(mktemp -d)
gh run download "$id" --pattern "$pattern" -D "$tmp"
mkdir -p "$dest"
n=$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | wc -l)
if [[ "$n" -eq 1 ]]; then cp -R "$tmp"/*/. "$dest"/; else cp -R "$tmp"/. "$dest"/; fi
gh run view "$id" --json url,headSha,headBranch,conclusion,displayTitle > "$dest/run-info.json"
rm -rf "$tmp"
echo "run $id -> $dest"; cat "$dest/run-info.json"; echo
