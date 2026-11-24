#!/usr/bin/env python3
"""H4: rule-based triage of dependency advisories versus CVSS-only ordering.

Step 1 (before anyone sees rule outcomes) - make the rating sheet:
    python3 analysis/h4_triage.py --reports results/h1/onera-bill-baseline --make-template triage/relevance-labels.csv
  Two raters fill 'rater1' and 'rater2' independently with: relevant / not-relevant,
  then agree a 'final' label. Commit the file before step 2.

Step 2 - evaluate:
    python3 analysis/h4_triage.py --reports results/h1/onera-bill-baseline \
        --evidence security/dependency-evidence.json --labels triage/relevance-labels.csv \
        [--epss triage/epss.csv] --out results/h4

Thresholds (fixed in advance): queue reduction >= 30% versus CVSS-only (medium or higher);
100% of advisories labelled relevant stay in Fix-now or Review; Cohen's kappa >= 0.60.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tools"))
from stats import cohen_kappa  # noqa: E402
from normalise import load_json, parse_composer, sbom_index  # noqa: E402
from gate import triage  # noqa: E402

CVSS_QUEUE = {"medium", "high", "critical"}


def records(reports):
    reports = Path(reports)
    idx = sbom_index(load_json(reports / "cyclonedx-sbom.json"))
    return parse_composer(load_json(reports / "composer-audit.json"), idx)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True, help="folder with composer-audit.json and cyclonedx-sbom.json")
    ap.add_argument("--make-template")
    ap.add_argument("--evidence", default="security/dependency-evidence.json")
    ap.add_argument("--policy", default="security/policy.json")
    ap.add_argument("--labels")
    ap.add_argument("--epss")
    ap.add_argument("--out", default="results/h4")
    a = ap.parse_args()
    recs = records(a.reports)

    if a.make_template:
        Path(a.make_template).parent.mkdir(parents=True, exist_ok=True)
        with open(a.make_template, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["advisory_id", "package", "version", "direct", "dev", "severity", "cve", "title",
                        "rater1", "rater2", "final", "note"])
            for r in recs:
                cve = next((x for x in r["aliases"] if x.startswith("CVE-")), "")
                w.writerow([r["id"], r["package"], r["version"], r["direct"], r["dev"], r["severity"] or "unscored",
                            cve, r["title"], "", "", "", ""])
        print(f"Rating sheet with {len(recs)} advisories written to {a.make_template}")
        return

    policy = load_json(a.policy)
    evidence = {k.lower(): v for k, v in ((load_json(a.evidence) or {}).get("packages", {})).items()}
    labels = {r["advisory_id"]: r for r in csv.DictReader(open(a.labels))} if a.labels else {}
    epss = {r["cve"]: r for r in csv.DictReader(open(a.epss))} if a.epss and Path(a.epss).exists() else {}

    rows = []
    for r in recs:
        outcome, rule, reason = triage(r, policy, evidence)
        lab = labels.get(r["id"], {})
        cve = next((x for x in r["aliases"] if x.startswith("CVE-")), "")
        rows.append({
            "advisory_id": r["id"], "package": r["package"], "direct": r["direct"], "dev": r["dev"],
            "severity": r["severity"] or "unscored", "fix_available": r["fix_available"], "cve": cve,
            "rule": rule, "outcome": outcome, "reason": reason,
            "cvss_queue": (r["severity"] or "") in CVSS_QUEUE,
            "rater1": lab.get("rater1", ""), "rater2": lab.get("rater2", ""), "final": lab.get("final", ""),
            "epss": epss.get(cve, {}).get("epss", ""), "epss_percentile": epss.get(cve, {}).get("percentile", ""),
        })

    q_cvss = sum(r["cvss_queue"] for r in rows)
    q_rules = sum(r["outcome"] in ("fix-now", "review") for r in rows)
    reduction = 1 - q_rules / q_cvss if q_cvss else None
    relevant = [r for r in rows if r["final"].strip().lower() == "relevant"]
    lost = [r for r in relevant if r["outcome"] not in ("fix-now", "review")]
    r1 = [r["rater1"].strip().lower() for r in rows if r["rater1"] and r["rater2"]]
    r2 = [r["rater2"].strip().lower() for r in rows if r["rater1"] and r["rater2"]]
    kappa = cohen_kappa(r1, r2) if r1 else None
    cvss_relevant_missed = [r for r in relevant if not r["cvss_queue"]]

    checks = {
        "queue reduction >= 30%": reduction is not None and reduction >= 0.30,
        "100% of relevant advisories kept": bool(labels) and not lost,
        "kappa >= 0.60": kappa is not None and kappa >= 0.60,
    }
    result = {
        "records": len(rows), "cvss_only_queue": q_cvss, "rules_queue": q_rules,
        "queue_reduction": None if reduction is None else round(reduction, 4),
        "outcomes": {o: sum(r["outcome"] == o for r in rows) for o in ("fix-now", "review", "defer")},
        "by_rule": {k: sum(r["rule"] == k for r in rows) for k in ("T1", "T2", "T3", "T4", "T5")},
        "relevant_final": len(relevant), "relevant_deferred_by_rules": [r["advisory_id"] for r in lost],
        "relevant_missed_by_cvss_only": [r["advisory_id"] for r in cvss_relevant_missed],
        "kappa": kappa, "rated_pairs": len(r1),
        "epss_subset_n": sum(1 for r in rows if r["cve"]),
        "checks": checks,
        "H4": "supported" if all(checks.values()) else ("inconclusive (labels missing)" if not labels else "not supported"),
    }
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "triage_table.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    (out / "h4.json").write_text(json.dumps(result, indent=2))
    for r in rows:
        print(f"{r['advisory_id']:22} {r['package']:26} {r['severity']:9} {r['rule']:3} {r['outcome']:8} final={r['final']}")
    print(json.dumps({k: v for k, v in result.items() if k not in ("relevant_deferred_by_rules",)}, indent=2))


if __name__ == "__main__":
    main()
