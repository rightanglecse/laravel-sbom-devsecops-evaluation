#!/usr/bin/env python3
"""Convert raw scanner reports into one list of normalised findings.

Usage:
    python3 tools/normalise.py --reports reports/ --out reports/findings.json

Inputs (all optional; whatever is present in the reports folder is read):
    composer-audit.json   Composer audit (--format=json)
    osv.json              OSV-Scanner JSON output (scan of the SBOM)
    cyclonedx-sbom.json   CycloneDX SBOM (used to enrich dependency findings)
    semgrep.sarif         Semgrep SARIF
    psalm.sarif           Psalm SARIF (taint analysis)
    gitleaks.sarif        Gitleaks SARIF
    phpstan.json          PHPStan JSON

Only the Python standard library is used.
"""
import argparse
import json
import os
import re
from pathlib import Path

IGNORED_PREFIXES = ("vendor/", "node_modules/", "tests/", "storage/", "bootstrap/cache/")
SEVERITY_ORDER = {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def clean_path(uri):
    if not uri:
        return ""
    uri = re.sub(r"^file://", "", uri)
    workspace = os.environ.get("GITHUB_WORKSPACE", "").rstrip("/")
    if workspace and uri.startswith(workspace + "/"):
        return uri[len(workspace) + 1:]
    m = re.search(r"/home/runner/work/[^/]+/[^/]+/(.*)", uri)
    if m:
        return m.group(1)
    if "/github/workspace/" in uri:
        return uri.split("/github/workspace/", 1)[1]
    while uri.startswith("./"):
        uri = uri[2:]
    return uri


def cvss_to_label(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return None


# ---------------------------------------------------------------- SBOM

def sbom_index(sbom):
    """Return {package name: {version, direct, dev}} from a CycloneDX SBOM."""
    index = {}
    if not sbom:
        return index
    root = sbom.get("metadata", {}).get("component", {}).get("bom-ref")
    graph = {d["ref"]: d.get("dependsOn", []) for d in sbom.get("dependencies", [])}
    direct_refs = set(graph.get(root, []))
    for c in sbom.get("components", []):
        name = (c.get("group", "") + "/" + c["name"]).strip("/").lower()
        props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
        index[name] = {
            "version": c.get("version"),
            "direct": c.get("bom-ref") in direct_refs,
            "dev": props.get("cdx:composer:package:isDevRequirement") == "true",
        }
    return index


# ---------------------------------------------------------------- dependency reports

def fix_available(constraint):
    """A Packagist constraint such as '>=7.0,<7.15.2' has an upper bound, so a
    fixed version exists. Returns True, False or None (unknown)."""
    if not constraint:
        return None
    parts = [p.strip() for p in str(constraint).split("|")]
    return all("<" in p for p in parts if p)


def parse_composer(audit, sbom_idx):
    findings = []
    if not audit:
        return findings
    advisories = audit.get("advisories") or {}
    if isinstance(advisories, list):  # Composer prints [] when there are none
        advisories = {}
    for package, items in advisories.items():
        if isinstance(items, dict):
            items = list(items.values())
        meta = sbom_idx.get(package.lower(), {})
        for a in items:
            ids = {a.get("advisoryId"), a.get("cve")}
            for src in a.get("sources", []) or []:
                ids.add(src.get("remoteId"))
            ids.update(re.findall(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", a.get("link") or ""))
            findings.append({
                "tool": "composer-audit",
                "kind": "dependency",
                "id": a.get("advisoryId"),
                "aliases": sorted(i for i in ids if i),
                "title": a.get("title"),
                "package": package,
                "version": meta.get("version"),
                "direct": meta.get("direct"),
                "dev": meta.get("dev"),
                "severity": (a.get("severity") or None) and str(a.get("severity")).lower(),
                "fix_available": fix_available(a.get("affectedVersions")),
                "affected": a.get("affectedVersions"),
            })
    return findings


def parse_osv(osv, sbom_idx):
    findings = []
    if not osv:
        return findings
    for result in osv.get("results", []) or []:
        for pkg in result.get("packages", []) or []:
            p = pkg.get("package", {})
            name = (p.get("name") or "").lower()
            meta = sbom_idx.get(name, {})
            group_sev = {}
            for g in pkg.get("groups", []) or []:
                for i in g.get("ids", []):
                    group_sev[i] = g.get("max_severity")
            for v in pkg.get("vulnerabilities", []) or []:
                sev = (v.get("database_specific") or {}).get("severity")
                sev = str(sev).lower() if sev else cvss_to_label(group_sev.get(v.get("id")))
                fixed = None
                for aff in v.get("affected", []) or []:
                    for rng in aff.get("ranges", []) or []:
                        if any("fixed" in e for e in rng.get("events", [])):
                            fixed = True
                findings.append({
                    "tool": "osv-scanner",
                    "kind": "dependency",
                    "id": v.get("id"),
                    "aliases": sorted(set([v.get("id")] + (v.get("aliases") or []))),
                    "title": v.get("summary"),
                    "package": name,
                    "version": p.get("version"),
                    "direct": meta.get("direct"),
                    "dev": meta.get("dev"),
                    "severity": sev if sev in SEVERITY_ORDER else None,
                    "fix_available": fixed,
                })
    return findings


# ---------------------------------------------------------------- code reports

def parse_sarif(sarif, tool, kind):
    findings = []
    if not sarif:
        return findings
    for run in sarif.get("runs", []) or []:
        rules = {}
        for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
            rules[r.get("id")] = r
        for res in run.get("results", []) or []:
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            path = clean_path(phys.get("artifactLocation", {}).get("uri"))
            region = phys.get("region", {})
            rule_id = res.get("ruleId") or ""
            level = res.get("level") or (rules.get(rule_id, {}).get("defaultConfiguration", {}) or {}).get("level")
            findings.append({
                "tool": tool,
                "kind": kind,
                "id": rule_id,
                "rule_short": rule_id.split(".")[-1],
                "file": path,
                "line": region.get("startLine"),
                "end_line": region.get("endLine") or region.get("startLine"),
                "level": level or ("error" if kind == "secret" else "warning"),
                "message": (res.get("message") or {}).get("text", "")[:300],
            })
    return findings


def parse_phpstan(report):
    findings = []
    if not report:
        return findings
    for path, data in (report.get("files") or {}).items():
        for m in data.get("messages", []):
            findings.append({
                "tool": "phpstan", "kind": "quality", "id": m.get("identifier") or "phpstan",
                "file": clean_path(path), "line": m.get("line"), "end_line": m.get("line"),
                "level": "note", "message": (m.get("message") or "")[:300],
            })
    return findings


def ignored(finding):
    f = finding.get("file") or ""
    return any(f.startswith(p) for p in IGNORED_PREFIXES)


def normalise(reports_dir):
    d = Path(reports_dir)
    sbom_idx = sbom_index(load_json(d / "cyclonedx-sbom.json"))
    findings = []
    findings += parse_composer(load_json(d / "composer-audit.json"), sbom_idx)
    findings += parse_osv(load_json(d / "osv.json"), sbom_idx)
    findings += parse_sarif(load_json(d / "semgrep.sarif"), "semgrep", "sast")
    findings += parse_sarif(load_json(d / "psalm.sarif"), "psalm", "sast")
    findings += parse_sarif(load_json(d / "gitleaks.sarif"), "gitleaks", "secret")
    findings += parse_phpstan(load_json(d / "phpstan.json"))
    findings = [f for f in findings if not ignored(f)]

    # Link dependency findings reported by more than one tool (shared alias).
    groups = []
    for f in (x for x in findings if x["kind"] == "dependency"):
        keys = set(a.upper() for a in f.get("aliases", []) if a)
        keys.add(f"{f['package']}|{f.get('id')}".upper())
        for g in groups:
            if g["keys"] & keys and g["package"] == f["package"]:
                g["keys"] |= keys
                g["members"].append(f)
                break
        else:
            groups.append({"keys": keys, "package": f["package"], "members": [f]})
    for n, g in enumerate(groups, 1):
        for f in g["members"]:
            f["dependency_group"] = n
    for n, f in enumerate(findings, 1):
        f["finding_no"] = n
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    findings = normalise(a.reports)
    Path(a.out).write_text(json.dumps(findings, indent=2))
    kinds = {}
    for f in findings:
        kinds[f["tool"]] = kinds.get(f["tool"], 0) + 1
    print(f"{len(findings)} findings: {kinds}")


if __name__ == "__main__":
    main()
