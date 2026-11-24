#!/usr/bin/env python3
"""H5: pipeline-time overhead of F over B0 (and B1), plus review burden.

Step 1: bash analysis/run_timing.sh timing      (writes results/h5/runs.csv)
Step 2: python3 analysis/h5_timing.py            (fetches job timings with gh, writes results/h5/)

Wall-clock time of a run = last job completion - first job start (queue time excluded).
Threshold fixed in advance: median(F warm) - median(B0 warm) <= 90 s.
Test: two-sided Mann-Whitney U (exact), alpha = 0.05.

Review burden (optional): with --detection results/detection, counts the findings a reviewer
must open on the fixed (clean) branch: all security findings for B1 (no triage) versus the
Fix-now + Review findings of the F gate.
"""
import argparse
import csv
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tools"))
from stats import mann_whitney, median_iqr  # noqa: E402

THRESHOLD_S = 90


def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def jobs_for(run_id):
    out = subprocess.check_output(["gh", "api", f"repos/{{owner}}/{{repo}}/actions/runs/{run_id}/jobs?per_page=100"],
                                  text=True)
    return json.loads(out)["jobs"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="results/h5/runs.csv")
    ap.add_argument("--out", default="results/h5")
    ap.add_argument("--detection", help="results/detection folder for the review-burden count")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    cache_file = out / "jobs_cache.json"
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    rows, steps = [], {}
    for r in csv.DictReader(open(a.runs)):
        rid = r["run_id"]
        if rid not in cache:
            cache[rid] = jobs_for(rid)
        jobs = [j for j in cache[rid] if j.get("started_at") and j.get("completed_at")]
        if not jobs:
            continue
        start = min(ts(j["started_at"]) for j in jobs)
        end = max(ts(j["completed_at"]) for j in jobs)
        rows.append({**r, "seconds": round((end - start).total_seconds(), 1),
                     "conclusion": ";".join(sorted({j.get("conclusion") or "" for j in jobs}))})
        for j in jobs:
            for s in j.get("steps", []) or []:
                if s.get("started_at") and s.get("completed_at"):
                    k = (r["config"], r["cache"], j["name"], s["name"])
                    steps.setdefault(k, []).append((ts(s["completed_at"]) - ts(s["started_at"])).total_seconds())
    cache_file.write_text(json.dumps(cache))

    with open(out / "timing.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    with open(out / "steps.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["config", "cache", "job", "step", "n", "median_s", "q1_s", "q3_s"])
        for (c, cache_mode, job, step), vals in sorted(steps.items()):
            m, q1, q3 = median_iqr(vals)
            w.writerow([c, cache_mode, job, step, len(vals), m, q1, q3])

    def sel(cfg, mode):
        return [r["seconds"] for r in rows if r["config"] == cfg and r["cache"] == mode]

    summary = {}
    for mode in ("warm", "cold"):
        for cfg in ("B0", "B1", "F"):
            v = sel(cfg, mode)
            m, q1, q3 = median_iqr(v)
            summary[f"{cfg}_{mode}"] = {"n": len(v), "median": m, "q1": q1, "q3": q3,
                                        "min": min(v) if v else None, "max": max(v) if v else None}
    tests = {}
    for mode in ("warm", "cold"):
        for x in ("F", "B1"):
            u, p, method = mann_whitney(sel(x, mode), sel("B0", mode))
            mx, mb = summary[f"{x}_{mode}"]["median"], summary[f"B0_{mode}"]["median"]
            overhead = None if mx is None or mb is None else round(mx - mb, 1)
            tests[f"{x}_vs_B0_{mode}"] = {"U": u, "p": p, "method": method, "median_overhead_s": overhead,
                                          "overhead_pct": None if not overhead else round(100 * overhead / mb, 1)}
    over = tests["F_vs_B0_warm"]["median_overhead_s"]
    verdict = {"threshold_s": THRESHOLD_S, "F_minus_B0_warm_median_s": over,
               "H5": None if over is None else ("supported" if over <= THRESHOLD_S else "not supported")}

    burden = None
    if a.detection:
        from normalise import normalise, load_json
        b1 = [f for f in normalise(Path(a.detection) / "B1" / "fixed")
              if f["tool"] in ("semgrep", "gitleaks", "composer-audit")]
        fdir = Path(a.detection) / "F" / "fixed"
        gd = load_json(fdir / "gate-decision.json") or {}
        f_review = (gd.get("counts") or {}).get("fix-now", 0) + (gd.get("counts") or {}).get("review", 0)
        burden = {"B1_findings_to_inspect_on_clean_branch": len(b1),
                  "F_fix_now_plus_review_on_clean_branch": f_review,
                  "F_gate_decision_on_clean_branch": gd.get("decision")}

    result = {"summary": summary, "tests": tests, "verdict": verdict, "review_burden": burden}
    (out / "h5.json").write_text(json.dumps(result, indent=2))
    print(f"{'Config':10} {'n':>3} {'median':>8} {'IQR':>16}")
    for k, s in summary.items():
        print(f"{k:10} {s['n']:>3} {s['median']!s:>8} {str((s['q1'], s['q3'])):>16}")
    for k, t in tests.items():
        print(f"{k}: overhead {t['median_overhead_s']} s ({t['overhead_pct']}%), Mann-Whitney U={t['U']} p={t['p']} ({t['method']})")
    print("H5:", verdict)
    if burden:
        print("Review burden:", burden)


if __name__ == "__main__":
    main()
