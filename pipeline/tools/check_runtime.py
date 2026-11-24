#!/usr/bin/env python3
"""Confirm every seed is a real, working vulnerability.

A seed enters the benchmark only if its runtime test PASSES on the vulnerable
branch (the attack works) and FAILS on the fixed branch (the attack is stopped).

Usage:
  python3 tools/check_runtime.py --manifest seeds/manifest.csv \
      --vulnerable results/runtime-vulnerable/benchmark-junit.xml \
      --fixed results/runtime-fixed/benchmark-junit.xml --out results/runtime-check.csv
"""
import argparse
import csv
import xml.etree.ElementTree as ET


def outcomes(junit_path):
    """Return {test class short name: 'pass' | 'fail' | 'error' | 'skipped'}."""
    res = {}
    for tc in ET.parse(junit_path).getroot().iter("testcase"):
        cls = (tc.get("class") or tc.get("classname") or "").split("\\")[-1].split(".")[-1]
        state = "pass"
        for child in tc:
            if child.tag in ("failure", "error", "skipped"):
                state = "fail" if child.tag == "failure" else child.tag
        prev = res.get(cls)
        res[cls] = state if prev in (None, "pass") else prev
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--vulnerable", required=True)
    ap.add_argument("--fixed", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    vul, fix = outcomes(a.vulnerable), outcomes(a.fixed)
    rows, ok_count = [], 0
    for seed in csv.DictReader(open(a.manifest)):
        t = seed["runtime_test"]
        v, f = vul.get(t, "missing"), fix.get(t, "missing")
        ok = v == "pass" and f == "fail"
        ok_count += ok
        rows.append({"seed": seed["id"], "class": seed["class"], "test": t,
                     "vulnerable_branch": v, "fixed_branch": f, "verified": "yes" if ok else "NO"})
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print(f"{r['seed']}  vulnerable={r['vulnerable_branch']:8} fixed={r['fixed_branch']:8} verified={r['verified']}")
    print(f"\n{ok_count}/{len(rows)} seeds verified at runtime")


if __name__ == "__main__":
    main()
