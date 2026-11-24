#!/usr/bin/env bash
# Print the latest released versions so you can pin them in the workflow env blocks.
set -u
for r in semgrep/semgrep gitleaks/gitleaks google/osv-scanner CycloneDX/cyclonedx-php-composer vimeo/psalm; do
  printf "%-36s %s\n" "$r" "$(gh release view -R "$r" --json tagName --jq .tagName 2>/dev/null || echo '?')"
done
