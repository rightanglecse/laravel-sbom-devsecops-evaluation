#!/usr/bin/env bash
# Replace "uses: owner/repo@tag" with the full commit SHA (GitHub hardening guidance).
# Needs the GitHub CLI (gh) logged in. Usage: bash tools/pin_actions.sh .github/workflows/*.yml
set -euo pipefail
for wf in "$@"; do
  grep -oE 'uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[A-Za-z0-9_.-]+' "$wf" | sort -u | while read -r _ ref; do
    repo="${ref%@*}"; tag="${ref#*@}"
    [[ ${#tag} -eq 40 ]] && continue
    base=$(echo "$repo" | cut -d/ -f1-2)
    sha=$(gh api "repos/$base/commits/$tag" --jq .sha)
    sed -i.bak "s#uses: $repo@$tag\$#uses: $repo@$sha \# $tag#" "$wf"
    echo "$wf: $repo@$tag -> $sha"
  done
  rm -f "$wf.bak"
done
