#!/usr/bin/env python3
"""Build the report sets for gate scenarios G1-G10 (tests/gate-scenarios/).

Each scenario starts from a clean, complete report set and changes one thing.
Run: python3 tools/build_gate_scenarios.py tests/gate-scenarios
"""
import copy
import json
import shutil
import sys
from pathlib import Path

EMPTY_SARIF = lambda tool: {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool}}, "results": []}]}


def sbom(components):
    comps, deps, root_deps = [], [], []
    for name, version, direct, dev in components:
        group, short = name.split("/")
        ref = f"{name}-{version}.0.0"
        comps.append({"type": "library", "bom-ref": ref, "group": group, "name": short, "version": version,
                      "purl": f"pkg:composer/{name}@{version}",
                      "properties": [{"name": "cdx:composer:package:isDevRequirement", "value": str(dev).lower()}]})
        deps.append({"ref": ref, "dependsOn": []})
        if direct:
            root_deps.append(ref)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "bom-ref": "root", "name": "onera-bill"}},
            "components": comps, "dependencies": [{"ref": "root", "dependsOn": root_deps}] + deps}


BASE_COMPONENTS = [
    ("laravel/framework", "v12.62.0", True, False),
    ("guzzlehttp/guzzle", "7.12.1", False, False),
    ("symfony/yaml", "v7.4.13", False, True),
]


def advisory(pkg, adv_id, sev, affected, cve=None):
    return {"advisoryId": adv_id, "packageName": pkg, "affectedVersions": affected, "title": f"Test advisory {adv_id}",
            "cve": cve, "link": "", "sources": [], "severity": sev}


def sarif_result(tool, rule, level, path, line):
    s = EMPTY_SARIF(tool)
    s["runs"][0]["results"].append({"ruleId": rule, "level": level, "message": {"text": rule},
                                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                                        "region": {"startLine": line}}}]})
    return s


def base_reports():
    return {
        "composer-audit.json": {"advisories": [], "abandoned": [], "filter": []},
        "cyclonedx-sbom.json": sbom(BASE_COMPONENTS),
        "sbom-check.json": {"completeness": 1.0, "jaccard": 1.0, "lock_unchanged": True},
        "osv.json": {"results": []},
        "semgrep.sarif": EMPTY_SARIF("semgrep"),
        "psalm.sarif": EMPTY_SARIF("psalm"),
        "gitleaks.sarif": EMPTY_SARIF("gitleaks"),
    }


BASE_STATUS = {"composer-audit": (0, [0, 1, 2, 3]), "sbom": (0, [0]), "sbom-check": (0, [0]),
               "osv-scanner": (0, [0, 1]), "semgrep": (0, [0, 1]), "psalm": (0, [0, 1, 2]), "gitleaks": (0, [0, 2])}

CRITICAL_DIRECT = {"laravel/framework": [advisory("laravel/framework", "PKSA-g3", "critical", "<12.68.0", "CVE-2026-114509")]}

SCENARIOS = [
    ("G1", "Clean control: all mandatory reports present, no findings", "pass", 0, {}, {}, None, None),
    ("G2", "Synthetic secret committed in application code", "block", 1,
     {"gitleaks.sarif": sarif_result("gitleaks", "twilio-api-key", None, "app/Services/ClinicSmsGateway.php", 7)},
     {"gitleaks": (2, [0, 2])}, None, None),
    ("G3", "Direct dependency with a critical advisory and a fixed version", "block", 1,
     {"composer-audit.json": {"advisories": CRITICAL_DIRECT}}, {"composer-audit": (1, [0, 1, 2, 3])}, None, None),
    ("G4", "High-confidence SQL injection finding in production code", "block", 1,
     {"semgrep.sarif": sarif_result("semgrep", "security.laravel-raw-sql-concatenation", "error",
                                    "app/Http/Controllers/Clinic/PatientRecordController.php", 28)}, {}, None, None),
    ("G5", "Transitive advisory on a request-handling package; no use evidence", "review", 2,
     {"composer-audit.json": {"advisories": {"guzzlehttp/guzzle": [advisory("guzzlehttp/guzzle", "PKSA-g5", "high", "<7.15.2", "CVE-2026-69246")]}}},
     {"composer-audit": (1, [0, 1, 2, 3])}, None, None),
    ("G6", "Advisory without a severity score", "review", 2,
     {"composer-audit.json": {"advisories": {"guzzlehttp/guzzle": [advisory("guzzlehttp/guzzle", "PKSA-g6", None, "<7.15.2", "CVE-2026-0006")]}}},
     {"composer-audit": (1, [0, 1, 2, 3])}, None, None),
    ("G7", "SBOM report missing", "incomplete", 3, {"cyclonedx-sbom.json": None}, {"sbom": (1, [0])}, None, None),
    ("G8", "Scanner exits with an error and leaves an empty report", "incomplete", 3,
     {"semgrep.sarif": ""}, {"semgrep": (2, [0, 1])}, None, None),
    ("G9", "Blocking advisory covered by an approved, unexpired exception", "pass", 0,
     {"composer-audit.json": {"advisories": CRITICAL_DIRECT}}, {"composer-audit": (1, [0, 1, 2, 3])}, None,
     {"exceptions": [{"tool": "composer-audit", "id": "CVE-2026-114509", "owner": "thesis author",
                      "reason": "upgrade scheduled in release 1.4; TokenGuard not used (session auth only)",
                      "expires": "2099-12-31"}]}),
    ("G10", "Advisory only in a development package with no production use", "pass", 0,
     {"composer-audit.json": {"advisories": {"symfony/yaml": [advisory("symfony/yaml", "PKSA-g10", "high", "<7.4.18", "CVE-2026-109413")]}}},
     {"composer-audit": (1, [0, 1, 2, 3])}, {"packages": {"symfony/yaml": {"production_use": False, "input_path": False,
                                                                           "note": "require-dev only"}}}, None),
]


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/gate-scenarios")
    if out.exists():
        shutil.rmtree(out)
    for sid, desc, decision, code, changes, status_changes, evidence, exceptions in SCENARIOS:
        d = out / sid / "reports"
        (d / "status").mkdir(parents=True)
        reports = base_reports()
        reports.update(changes)
        for name, content in reports.items():
            if content is None:
                continue
            (d / name).write_text(content if isinstance(content, str) else json.dumps(content, indent=2))
        status = copy.deepcopy(BASE_STATUS)
        status.update(status_changes)
        for name, (exit_code, ok) in status.items():
            (d / "status" / f"{name}.json").write_text(json.dumps({"name": name, "exit_code": exit_code, "ok_codes": ok}))
        (out / sid / "expected.json").write_text(json.dumps(
            {"id": sid, "description": desc, "expected_decision": decision, "expected_exit": code}, indent=2))
        if evidence:
            (out / sid / "evidence.json").write_text(json.dumps(evidence, indent=2))
        if exceptions:
            (out / sid / "exceptions.json").write_text(json.dumps(exceptions, indent=2))
    print(f"built {len(SCENARIOS)} scenarios in {out}")


if __name__ == "__main__":
    main()
