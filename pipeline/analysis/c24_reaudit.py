#!/usr/bin/env python3
"""C24: before/after management of the dependency advisories.

Usage:
  python3 analysis/c24_reaudit.py --before results/h1/onera-bill-baseline \
      --after results/h1/onera-bill-updated --out results/c24
Writes decision_record.csv (one row per original advisory). Fill 'decision' and 'reason'
for any row that is not resolved by the update (accept / not affected), then keep the file.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
from normalise import load_json, parse_composer, sbom_index  # noqa: E402


def state(folder):
    folder = Path(folder)
    idx = sbom_index(load_json(folder / "cyclonedx-sbom.json"))
    return idx, parse_composer(load_json(folder / "composer-audit.json"), idx)


ap = argparse.ArgumentParser()
ap.add_argument("--before", required=True)
ap.add_argument("--after", required=True)
ap.add_argument("--out", default="results/c24")
a = ap.parse_args()
idx_b, recs_b = state(a.before)
idx_a, recs_a = state(a.after)
after_ids = {r["id"] for r in recs_a}
rows = []
for r in recs_b:
    resolved = r["id"] not in after_ids
    rows.append({
        "advisory": r["id"], "cve": next((x for x in r["aliases"] if x.startswith("CVE-")), ""),
        "package": r["package"], "severity": r["severity"] or "unscored",
        "version_before": idx_b.get(r["package"], {}).get("version"),
        "version_after": idx_a.get(r["package"], {}).get("version"),
        "decision": "fix" if resolved else "", "reason": "fixed by update" if resolved else "",
        "reaudit": "clear" if resolved else "still reported",
    })
out = Path(a.out)
out.mkdir(parents=True, exist_ok=True)
with open(out / "decision_record.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)
pk = {}
for r in rows:
    p = pk.setdefault(r["package"], {"before": r["version_before"], "after": r["version_after"], "records": 0, "cleared": 0})
    p["records"] += 1
    p["cleared"] += r["reaudit"] == "clear"
summary = {"records_before": len(recs_b), "records_after": len(recs_a), "packages": pk,
           "new_after_update": [r["id"] for r in recs_a if r["id"] not in {x["id"] for x in recs_b}]}
(out / "c24.json").write_text(json.dumps(summary, indent=2))
for name, p in pk.items():
    print(f"{name:26} {p['before']!s:10} -> {p['after']!s:10} cleared {p['cleared']}/{p['records']}")
print(f"\nAdvisory records: {len(recs_b)} before, {len(recs_a)} after the update")
