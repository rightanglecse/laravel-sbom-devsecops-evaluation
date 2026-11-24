#!/usr/bin/env python3
"""H1: SBOM validity, completeness and use for vulnerability matching.

Reads one or more F report folders (main subject and the secondary open-source subjects).
Each folder needs: sbom-check.json, composer-audit.json, osv.json.

Thresholds (fixed in advance): schema valid; completeness = 1.00; Jaccard >= 0.90;
OSV-Scanner on the SBOM reproduces >= 90% of the Composer advisories.

Usage:
    python3 analysis/h1_sbom.py --subject onera-bill=results/h1/onera-bill \
        --subject firefly-iii=results/h1/firefly-iii --out results/h1
"""
import argparse
import json
import re
import sys
from pathlib import Path

GHSA = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def load(p):
    try:
        return json.loads(Path(p).read_text())
    except (OSError, ValueError):
        return None


def composer_records(audit):
    adv = (audit or {}).get("advisories") or {}
    if isinstance(adv, list):
        return []
    out = []
    for pkg, items in adv.items():
        items = list(items.values()) if isinstance(items, dict) else items
        for a in items:
            ids = set()
            for field in (a.get("cve"), a.get("link"), json.dumps(a.get("sources", []))):
                if field:
                    ids |= {m.upper() for m in GHSA.findall(field)} | {m.upper() for m in CVE.findall(field)}
            out.append({"package": pkg.lower(), "id": a.get("advisoryId"), "ids": ids, "title": a.get("title")})
    return out


def osv_records(osv):
    out = []
    for r in (osv or {}).get("results", []) or []:
        for p in r.get("packages", []) or []:
            name = (p.get("package", {}).get("name") or "").lower()
            for v in p.get("vulnerabilities", []) or []:
                ids = {v.get("id", "").upper()} | {x.upper() for x in v.get("aliases", []) or []}
                out.append({"package": name, "id": v.get("id"), "ids": ids})
    return out


def analyse(name, folder):
    folder = Path(folder)
    check = load(folder / "sbom-check.json") or {}
    comp = composer_records(load(folder / "composer-audit.json"))
    osv = osv_records(load(folder / "osv.json"))
    reproduced, missed = [], []
    for c in comp:
        hit = any(o["package"] == c["package"] and (o["ids"] & c["ids"]) for o in osv)
        (reproduced if hit else missed).append(c)
    osv_only = [o for o in osv if not any(o["package"] == c["package"] and (o["ids"] & c["ids"]) for c in comp)]
    agreement = len(reproduced) / len(comp) if comp else None
    schema = (check.get("schema") or {}).get("valid")
    res = {
        "subject": name,
        "schema_valid": schema,
        "schema_validator": (check.get("schema") or {}).get("validator"),
        "lock_packages": check.get("lock_packages"),
        "sbom_components": check.get("sbom_components"),
        "completeness": check.get("completeness"),
        "jaccard": check.get("jaccard"),
        "missing_from_sbom": check.get("missing_from_sbom"),
        "extra_in_sbom": check.get("extra_in_sbom"),
        "lock_unchanged": check.get("lock_unchanged"),
        "composer_advisories": len(comp),
        "reproduced_by_osv": len(reproduced),
        "agreement": None if agreement is None else round(agreement, 4),
        "missed_by_osv": [f"{m['package']} {m['id']} {sorted(m['ids'])}" for m in missed],
        "osv_only": [f"{o['package']} {o['id']}" for o in osv_only],
    }
    checks = {
        "schema valid": schema is True,
        "completeness = 1.00": res["completeness"] == 1.0,
        "Jaccard >= 0.90": (res["jaccard"] or 0) >= 0.90,
    }
    if agreement is not None:
        checks["OSV reproduces >= 90% of Composer advisories"] = agreement >= 0.90
    res["checks"] = checks
    res["H1"] = "supported" if all(checks.values()) else "not supported"
    if agreement is None:
        res["note"] = "no Composer advisories in this state, so matching agreement cannot be computed here"
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", action="append", required=True, help="name=folder")
    ap.add_argument("--out", default="results/h1")
    a = ap.parse_args()
    results = [analyse(*s.split("=", 1)) for s in a.subject]
    Path(a.out).mkdir(parents=True, exist_ok=True)
    (Path(a.out) / "h1.json").write_text(json.dumps(results, indent=2))
    for r in results:
        print(f"\n== {r['subject']} ==")
        for k in ("schema_valid", "lock_packages", "sbom_components", "completeness", "jaccard", "lock_unchanged",
                  "composer_advisories", "reproduced_by_osv", "agreement"):
            print(f"  {k:22} {r[k]}")
        if r["missing_from_sbom"]:
            print("  missing from SBOM:", r["missing_from_sbom"][:10])
        if r["extra_in_sbom"]:
            print("  extra in SBOM:", r["extra_in_sbom"][:10])
        if r["missed_by_osv"]:
            print("  Composer advisories not found by OSV:", *r["missed_by_osv"], sep="\n    ")
        print("  checks:", r["checks"], "->", r["H1"], r.get("note", ""))


if __name__ == "__main__":
    sys.exit(main())
