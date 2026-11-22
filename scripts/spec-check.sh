#!/usr/bin/env bash
# Fails if any acceptance criterion in specs/features has no test citing it.
# Go tests cite with "spec: ID" (several IDs allowed: "spec: GW-001, GW-002").
# Playwright tests cite with "[ID]" in the test title.
set -euo pipefail
cd "$(dirname "$0")/.."

ids=$(grep -ohE '\*\*[A-Z]+-[0-9]{3}\*\*' specs/features/*.md | tr -d '*' | sort -u)
cited=$( { grep -rhoE 'spec: [A-Z]+-[0-9]{3}([, ]+[A-Z]+-[0-9]{3})*' --include='*_test.go' . 2>/dev/null || true;
           grep -rhoE '\[[A-Z]+-[0-9]{3}\]' test/e2e --include='*.ts' 2>/dev/null || true; } \
         | { grep -oE '[A-Z]+-[0-9]{3}' || true; } | sort -u)

missing=$(comm -23 <(echo "$ids") <(echo "$cited"))
total=$(echo "$ids" | wc -l | tr -d ' ')
covered=$(comm -12 <(echo "$ids") <(echo "$cited") | wc -l | tr -d ' ')

echo "spec coverage: $covered / $total criteria have tests"
if [[ -n "$missing" ]]; then
  echo "missing tests for:"; echo "$missing" | sed 's/^/  - /'
  exit 1
fi
