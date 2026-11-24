#!/usr/bin/env python3
"""Four-state security gate.

Exit codes: 0 pass, 1 block, 2 review, 3 incomplete evidence.
Precedence: incomplete > block > review > pass.

Usage:
    python3 tools/gate.py --reports reports/ \
        --policy security/policy.json \
        --exceptions security/exceptions.json \
        --evidence security/dependency-evidence.json \
        --out reports/gate-decision.json

The reports folder must contain status/<name>.json for each mandatory report,
written by tools/run_step.sh, so that a crashed scanner is never read as clean.
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalise import normalise, load_json  # noqa: E402

PASS, BLOCK, REVIEW, INCOMPLETE = 0, 1, 2, 3
DECISION_NAME = {PASS: "pass", BLOCK: "block", REVIEW: "review", INCOMPLETE: "incomplete"}

# What a report must contain to count as a real report.
SHAPE_CHECKS = {
    ".sarif": lambda d: isinstance(d, dict) and isinstance(d.get("runs"), list),
    "composer-audit.json": lambda d: isinstance(d, dict) and "advisories" in d,
    "cyclonedx-sbom.json": lambda d: isinstance(d, dict) and isinstance(d.get("components"), list) and len(d["components"]) > 0,
    "osv.json": lambda d: isinstance(d, dict) and "results" in d,
    "sbom-check.json": lambda d: isinstance(d, dict) and "lock_unchanged" in d,
    "phpstan.json": lambda d: isinstance(d, dict) and "totals" in d,
}


def shape_ok(filename, data):
    for suffix, check in SHAPE_CHECKS.items():
        if filename.endswith(suffix):
            return check(data)
    return data is not None


def check_evidence(reports, policy):
    """Return a list of problems that make the evidence incomplete."""
    problems = []
    for item in policy["mandatory_reports"]:
        path = reports / item["file"]
        status = load_json(reports / "status" / f"{item['status']}.json")
        if status is None:
            problems.append(f"{item['name']}: no status record (step did not run)")
            continue
        if status.get("exit_code") not in status.get("ok_codes", [0]):
            problems.append(f"{item['name']}: tool exited with code {status.get('exit_code')}")
        if not path.exists() or path.stat().st_size == 0:
            problems.append(f"{item['name']}: report {item['file']} missing or empty")
            continue
        data = load_json(path)
        if not shape_ok(item["file"], data):
            problems.append(f"{item['name']}: report {item['file']} unreadable or malformed")
            continue
        if item["file"] == "sbom-check.json" and data.get("lock_unchanged") is not True:
            problems.append("sbom-check: composer.json/composer.lock changed during the run")
    return problems


def exception_for(finding, exceptions, today):
    for ex in exceptions:
        keys = [k for k in ("tool", "id", "package", "file") if ex.get(k)]
        if not keys:
            continue
        ok = True
        for k in keys:
            if k == "id":
                ids = {finding.get("id")} | set(finding.get("aliases", []))
                ok &= ex["id"] in ids
            else:
                ok &= finding.get(k) == ex[k]
        if ok:
            expired = dt.date.fromisoformat(ex["expires"]) < today
            return ex, expired
    return None, False


def triage(f, policy, evidence):
    """Apply rules T1-T5 to one finding. Returns (outcome, rule, reason)."""
    kind = f["kind"]
    if kind == "quality":
        return "info", "-", "type/quality finding; not used by the gate"

    if kind == "secret":
        return "fix-now", "T3", "secret committed in application code"

    if kind == "sast":
        level = (f.get("level") or "").lower()
        rule = f.get("id") or ""
        if f["tool"] == "psalm" and rule.startswith("Tainted"):
            return "fix-now", "T3", "taint flow from user input to a sink"
        if level in policy["sast_block_levels"]:
            return "fix-now", "T3", f"high-confidence SAST finding ({level})"
        if level in policy["sast_review_levels"]:
            return "review", "T4", f"medium-confidence SAST finding ({level})"
        return "info", "-", f"low-confidence SAST finding ({level})"

    # dependency findings
    sev = f.get("severity")
    if sev is None or f.get("dev") is None or f.get("fix_available") is None:
        return "review", "T1", "required information missing (severity, scope or fix status)"
    ev = evidence.get(f["package"].lower(), {})
    if f.get("dev") and ev.get("production_use") is not True:
        return "defer", "T2", "development-only package; not installed in production"
    if f.get("direct") and f.get("fix_available") and sev in policy["block_severities"]:
        return "fix-now", "T3", f"direct dependency, {sev}, fixed version available"
    if ev.get("input_path") is False:
        return "defer", "T5", "recorded evidence: package not on a user-input path; scheduled update"
    if ev.get("input_path") is True:
        return "review", "T4", "package on a user-input path"
    return "review", "T4", "no input-path evidence recorded"


def git_sha():
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def run_gate(reports_dir, policy, exceptions, evidence, today=None):
    reports = Path(reports_dir)
    today = today or dt.date.today()
    problems = check_evidence(reports, policy)
    findings = normalise(reports)

    log, seen_groups = [], set()
    counts = {"fix-now": 0, "review": 0, "defer": 0, "info": 0, "excepted": 0}
    for f in findings:
        group = f.get("dependency_group")
        if group is not None:
            if group in seen_groups:
                continue  # same advisory already triaged from another tool
            seen_groups.add(group)
        outcome, rule, reason = triage(f, policy, evidence)
        if outcome in ("fix-now", "review"):
            ex, expired = exception_for(f, exceptions, today)
            if ex and not expired:
                outcome, rule = "excepted", "EX"
                reason = f"approved exception (owner {ex.get('owner')}, expires {ex['expires']}): {ex.get('reason')}"
            elif ex and expired:
                reason += f"; exception expired on {ex['expires']}"
        counts[outcome] += 1
        log.append({
            "finding_no": f["finding_no"], "tool": f["tool"], "kind": f["kind"], "id": f.get("id"),
            "package": f.get("package"), "file": f.get("file"), "line": f.get("line"),
            "severity": f.get("severity") or f.get("level"), "outcome": outcome, "rule": rule, "reason": reason,
        })

    if problems:
        code = INCOMPLETE
    elif counts["fix-now"]:
        code = BLOCK
    elif counts["review"]:
        code = REVIEW
    else:
        code = PASS

    return {
        "decision": DECISION_NAME[code],
        "exit_code": code,
        "commit": git_sha(),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "evaluated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "evidence_problems": problems,
        "counts": counts,
        "triage_log": log,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True)
    ap.add_argument("--policy", default="security/policy.json")
    ap.add_argument("--exceptions", default="security/exceptions.json")
    ap.add_argument("--evidence", default="security/dependency-evidence.json")
    ap.add_argument("--out", required=True)
    ap.add_argument("--today", help="YYYY-MM-DD; fixes the date for repeatable tests")
    a = ap.parse_args()

    policy = load_json(a.policy)
    if policy is None:
        print(f"cannot read policy {a.policy}", file=sys.stderr)
        sys.exit(INCOMPLETE)
    exceptions = (load_json(a.exceptions) or {}).get("exceptions", [])
    evidence = {k.lower(): v for k, v in ((load_json(a.evidence) or {}).get("packages", {})).items()}
    today = dt.date.fromisoformat(a.today) if a.today else None

    result = run_gate(a.reports, policy, exceptions, evidence, today)
    Path(a.out).write_text(json.dumps(result, indent=2))
    print(f"GATE DECISION: {result['decision'].upper()} (exit {result['exit_code']})")
    for p in result["evidence_problems"]:
        print(f"  incomplete: {p}")
    print(f"  counts: {result['counts']}")
    sys.exit(result["exit_code"])


if __name__ == "__main__":
    main()
