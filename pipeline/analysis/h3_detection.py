#!/usr/bin/env python3
"""H3: detection of the seeded vulnerabilities by B0, B1 and F.

Expected folder layout (artifacts downloaded with analysis/collect.sh):
    results/detection/<CONFIG>/<variant>/   CONFIG = B0 | B1 | F, variant = vulnerable | fixed
each holding the raw reports of one run (semgrep.sarif, psalm.sarif, gitleaks.sarif, phpstan.json ...).

Matching rules (fixed before the runs, see PREREGISTRATION.md):
  * TP  - a seed counts as detected if any finding of an allowed tool lies in one of the
          seed's files within its line range +/- 2 lines.
  * FP  - every security finding (Semgrep, Psalm, Gitleaks) on the fixed branch, plus any
          security finding on the vulnerable branch inside a benchmark file that matches no seed.
          PHPStan findings are type checks, so they can earn a TP but are never counted as FP.
          Each FP candidate is listed in fp_review.csv for manual verification.
  * FN  - a seed with no matching finding.

Usage:
    python3 analysis/h3_detection.py --manifest seeds/manifest.csv --results results/detection \
        --fp-review analysis/fp_review.csv --out results/h3
"""
import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tools"))
from stats import clopper_pearson, mcnemar_exact  # noqa: E402
from normalise import normalise  # noqa: E402

TOOLS = {"B0": {"phpstan"}, "B1": {"phpstan", "semgrep", "gitleaks"}, "F": {"phpstan", "semgrep", "psalm", "gitleaks"}}
SECURITY_TOOLS = {"semgrep", "psalm", "gitleaks"}
TOLERANCE = 2
BENCH_PREFIXES = ("app/Http/Controllers/Clinic/", "app/Models/StaffProfile.php", "app/Models/Clinic",
                  "app/Services/ClinicSmsGateway.php", "app/Providers/ClinicServiceProvider.php",
                  "app/Policies/Clinic", "config/clinic.php", "resources/views/clinic/", "routes/clinic.php")
THRESHOLDS = {"recall_F": 0.60, "precision_F": 0.70, "alpha": 0.05}


def parse_locations(text):
    locs = []
    for part in text.split(";"):
        path, rng = part.rsplit(":", 1)
        a, b = rng.split("-")
        locs.append((path.strip(), int(a), int(b)))
    return locs


def code_findings(folder, config):
    if not folder.exists():
        return None
    out = []
    for f in normalise(folder):
        if f["kind"] in ("sast", "secret", "quality") and f["tool"] in TOOLS[config]:
            out.append(f)
    return out


def matches(f, loc):
    path, a, b = loc
    line = f.get("line") or 0
    return f.get("file") == path and a - TOLERANCE <= line <= b + TOLERANCE


def key(f):
    return f"{f['tool']}|{f.get('rule_short') or f.get('id')}|{f.get('file')}|{f.get('line')}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="seeds/manifest.csv")
    ap.add_argument("--results", default="results/detection")
    ap.add_argument("--fp-review", default="analysis/fp_review.csv")
    ap.add_argument("--out", default="results/h3")
    a = ap.parse_args()

    seeds = list(csv.DictReader(open(a.manifest)))
    for s in seeds:
        s["locs"] = parse_locations(s["locations"])
    verdicts = {}
    if Path(a.fp_review).exists():
        for r in csv.DictReader(open(a.fp_review)):
            if r.get("verdict"):
                verdicts[r["key"]] = r["verdict"].strip().lower()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    detection, summary, fp_rows = {}, {}, []
    for config in ("B0", "B1", "F"):
        vul = code_findings(Path(a.results) / config / "vulnerable", config)
        fix = code_findings(Path(a.results) / config / "fixed", config)
        if vul is None or fix is None:
            print(f"[{config}] missing results folder - skipped")
            continue
        detected, by_tool = [], {}
        for s in seeds:
            hits = [f for f in vul if any(matches(f, loc) for loc in s["locs"])]
            detected.append(1 if hits else 0)
            by_tool[s["id"]] = sorted({f"{h['tool']}:{h.get('rule_short') or h.get('id')}" for h in hits})
        detection[config] = detected

        candidates = {}
        for f in fix:
            if f["tool"] in SECURITY_TOOLS:
                candidates[key(f)] = ("fixed", f)
        for f in vul:
            if f["tool"] in SECURITY_TOOLS and (f.get("file") or "").startswith(BENCH_PREFIXES) \
                    and not any(matches(f, loc) for s in seeds for loc in s["locs"]):
                candidates.setdefault(key(f), ("vulnerable", f))
        fp, true_issue, unreviewed = 0, 0, 0
        for k, (branch, f) in sorted(candidates.items()):
            v = verdicts.get(k, "")
            if v == "true-issue":
                true_issue += 1
            else:
                fp += 1
                unreviewed += v == ""
            fp_rows.append({"config": config, "branch": branch, "key": k, "tool": f["tool"],
                            "rule": f.get("rule_short") or f.get("id"), "file": f.get("file"), "line": f.get("line"),
                            "message": (f.get("message") or "")[:160], "verdict": v})

        tp = sum(detected)
        fn = len(seeds) - tp
        recall = tp / len(seeds)
        precision = tp / (tp + fp) if tp + fp else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
        summary[config] = {
            "TP": tp, "FN": fn, "FP": fp, "FP_unreviewed": unreviewed, "true_issues_outside_benchmark": true_issue,
            "recall": round(recall, 4), "recall_ci95": clopper_pearson(tp, len(seeds)),
            "precision": None if precision is None else round(precision, 4),
            "precision_ci95": clopper_pearson(tp, tp + fp) if tp + fp else (None, None),
            "f1": None if f1 is None else round(f1, 4),
            "detected_by": by_tool,
        }

    tests = {}
    for x, y in (("F", "B1"), ("B1", "B0"), ("F", "B0")):
        if x in detection and y in detection:
            b = sum(1 for i, j in zip(detection[x], detection[y]) if i and not j)
            c = sum(1 for i, j in zip(detection[x], detection[y]) if j and not i)
            two, one = mcnemar_exact(b, c)
            tests[f"{x}_vs_{y}"] = {"only_first": b, "only_second": c, "p_two_sided": two, "p_one_sided": one}

    verdict = None
    if all(k in summary for k in ("B0", "B1", "F")):
        F = summary["F"]
        checks = {
            "recall_F >= 0.60": F["recall"] >= THRESHOLDS["recall_F"],
            "precision_F >= 0.70": F["precision"] is not None and F["precision"] >= THRESHOLDS["precision_F"],
            "recall F > B1 (McNemar p < 0.05)": F["recall"] > summary["B1"]["recall"] and tests["F_vs_B1"]["p_two_sided"] < 0.05,
            "recall B1 > B0 (McNemar p < 0.05)": summary["B1"]["recall"] > summary["B0"]["recall"] and tests["B1_vs_B0"]["p_two_sided"] < 0.05,
        }
        verdict = {"checks": checks, "H3": "supported" if all(checks.values()) else "not supported",
                   "note": "FP verdicts missing for some candidates" if any(s["FP_unreviewed"] for s in summary.values()) else ""}

    # per-class view
    per_class = {}
    for i, s in enumerate(seeds):
        row = per_class.setdefault(s["class"], {"seeds": 0})
        row["seeds"] += 1
        for config in detection:
            row[config] = row.get(config, 0) + detection[config][i]

    with open(out / "detection_matrix.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["seed", "class", "cwe"] + list(detection) + [f"{c}_detected_by" for c in detection])
        for i, s in enumerate(seeds):
            w.writerow([s["id"], s["class"], s["cwe"]] + [detection[c][i] for c in detection]
                       + ["; ".join(summary[c]["detected_by"][s["id"]]) for c in detection])
    if fp_rows:
        with open(out / "fp_candidates.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fp_rows[0].keys())
            w.writeheader()
            w.writerows(fp_rows)
    result = {"summary": summary, "mcnemar": tests, "per_class": per_class, "verdict": verdict, "thresholds": THRESHOLDS}
    (out / "h3.json").write_text(json.dumps(result, indent=2))

    print(f"{'Config':6} {'TP':>3} {'FN':>3} {'FP':>3}  Recall (95% CI)          Precision (95% CI)")
    for c, s in summary.items():
        p = "n/a" if s["precision"] is None else f"{s['precision']:.2f} {s['precision_ci95']}"
        print(f"{c:6} {s['TP']:>3} {s['FN']:>3} {s['FP']:>3}  {s['recall']:.2f} {s['recall_ci95']}   {p}")
    for k, t in tests.items():
        print(f"McNemar {k}: {t['only_first']} vs {t['only_second']} discordant, p = {t['p_two_sided']}")
    if verdict:
        print("H3:", verdict["H3"], verdict["checks"], verdict["note"])
    print(f"\nFP candidates written to {out / 'fp_candidates.csv'} - copy the 'key' and add a 'verdict' "
          f"(fp / true-issue) in {a.fp_review}, then re-run.")


if __name__ == "__main__":
    main()
