#!/usr/bin/env bash
# Controlled timing experiment for H5: 10 warm + 3 cold runs per configuration,
# interleaved B0, B1, F on ONE fixed commit (the branch given as $1, default "timing").
# One priming run per configuration fills the Composer cache and is not counted.
# Needs the GitHub CLI (gh auth login). Takes roughly 1.5 to 2 hours.
#   bash analysis/run_timing.sh timing
set -euo pipefail
REF="${1:-timing}"
OUT=results/h5
mkdir -p "$OUT"
echo "order,config,cache,run_id" > "$OUT/runs.csv"

trigger() {  # $1 workflow file, $2 cold true|false ; prints the run id
  local wf="$1" cold="$2" before id=""
  before=$(gh run list --workflow "$wf" --event workflow_dispatch -L 1 --json databaseId --jq '.[0].databaseId // 0')
  gh workflow run "$wf" --ref "$REF" -f cold="$cold" >&2
  for _ in $(seq 1 40); do
    sleep 5
    id=$(gh run list --workflow "$wf" --event workflow_dispatch -L 1 --json databaseId --jq '.[0].databaseId // 0')
    [[ "$id" != "$before" ]] && break
  done
  gh run watch "$id" --interval 10 > /dev/null 2>&1 || true
  echo "$id"
}

echo "Priming the cache (not counted)..." >&2
for wf in b0.yml b1.yml f.yml; do trigger "$wf" false > /dev/null; done

n=0
for rep in $(seq 1 10); do
  for cfg in B0 B1 F; do
    wf="$(echo "$cfg" | tr 'A-Z' 'a-z').yml"
    id=$(trigger "$wf" false); n=$((n+1))
    echo "$n,$cfg,warm,$id" >> "$OUT/runs.csv"; echo "warm $rep/10 $cfg -> run $id" >&2
  done
done
for rep in 1 2 3; do
  for cfg in B0 B1 F; do
    wf="$(echo "$cfg" | tr 'A-Z' 'a-z').yml"
    id=$(trigger "$wf" true); n=$((n+1))
    echo "$n,$cfg,cold,$id" >> "$OUT/runs.csv"; echo "cold $rep/3 $cfg -> run $id" >&2
  done
done
echo "Done. Run list: $OUT/runs.csv  Next: python3 analysis/h5_timing.py" >&2
