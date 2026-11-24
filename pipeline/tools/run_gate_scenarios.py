#!/usr/bin/env python3
"""Run the gate on every scenario folder and compare with the expected decision.

Each scenario folder contains:
  expected.json   {"id", "description", "expected_decision", "expected_exit"}
  reports/        the report set the gate reads (including reports/status/)
  evidence.json   optional, overrides security/dependency-evidence.json
  exceptions.json optional, overrides security/exceptions.json

Usage: python3 tools/run_gate_scenarios.py tests/gate-scenarios --out reports/gate-scenarios.json
Exit code 0 only if every scenario returns its expected decision.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import datetime as dt  # noqa: E402
from gate import run_gate  # noqa: E402
from normalise import load_json  # noqa: E402

TODAY = dt.date(2026, 11, 21)  # fixed so that exception expiry is repeatable


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--policy", default="security/policy.json")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    policy = load_json(a.policy)
    rows, all_ok = [], True
    for sc in sorted(Path(a.folder).iterdir(), key=lambda p: int(p.name[1:]) if p.name[1:].isdigit() else 999):
        if not (sc / "expected.json").exists():
            continue
        exp = load_json(sc / "expected.json")
        evidence = {k.lower(): v for k, v in (load_json(sc / "evidence.json") or {}).get("packages", {}).items()}
        exceptions = (load_json(sc / "exceptions.json") or {}).get("exceptions", [])
        result = run_gate(sc / "reports", policy, exceptions, evidence, TODAY)
        ok = result["exit_code"] == exp["expected_exit"]
        all_ok &= ok
        rows.append({
            "id": exp["id"], "description": exp["description"],
            "expected": f"{exp['expected_decision']} ({exp['expected_exit']})",
            "actual": f"{result['decision']} ({result['exit_code']})",
            "correct": ok,
            "reason": "; ".join(result["evidence_problems"]) or
                      "; ".join(sorted({f"{r['rule']}: {r['reason']}" for r in result["triage_log"]
                                        if r["outcome"] not in ("info",)})) or "no findings",
            "legacy_workflow": "success (no decision step; every scanner continue-on-error)",
        })
    Path(a.out).write_text(json.dumps({"scenarios": rows, "all_correct": all_ok,
                                       "correct": sum(r["correct"] for r in rows), "total": len(rows)}, indent=2))
    print(f"{'ID':4} {'Expected':16} {'Actual':16} OK  Reason")
    for r in rows:
        print(f"{r['id']:4} {r['expected']:16} {r['actual']:16} {'yes' if r['correct'] else 'NO ':3} {r['reason'][:90]}")
    print(f"\n{sum(r['correct'] for r in rows)}/{len(rows)} scenarios returned the expected decision")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
