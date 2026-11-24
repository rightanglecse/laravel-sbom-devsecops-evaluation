#!/usr/bin/env python3
"""Check a CycloneDX SBOM against composer.lock (H1 measures).

Usage:
    python3 tools/sbom_check.py --sbom reports/cyclonedx-sbom.json \
        --lock composer.lock --lock-diff-exit 0 --out reports/sbom-check.json

Measures:
  * schema validity (CycloneDX 1.5) - uses cyclonedx-python-lib if installed
  * completeness = |S n L| / |L| over (name, version) pairs
  * Jaccard      = |S n L| / |S u L|
  * development flag agreement (packages-dev vs isDevRequirement)
  * whether composer.json / composer.lock changed during the run
"""
import argparse
import json
from pathlib import Path


def pairs_from_lock(lock):
    prod = {(p["name"].lower(), p["version"]) for p in lock.get("packages", [])}
    dev = {(p["name"].lower(), p["version"]) for p in lock.get("packages-dev", [])}
    return prod, dev


def pairs_from_sbom(sbom):
    pairs, dev = set(), set()
    for c in sbom.get("components", []):
        name = (c.get("group", "") + "/" + c["name"]).strip("/").lower()
        pair = (name, c.get("version"))
        pairs.add(pair)
        for p in c.get("properties", []):
            if p.get("name") == "cdx:composer:package:isDevRequirement" and p.get("value") == "true":
                dev.add(pair)
    return pairs, dev


def validate_schema(text, spec):
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
        from importlib.metadata import version as pkg_version
    except ImportError:
        return {"valid": None, "validator": None, "note": "cyclonedx-python-lib not installed"}
    version = getattr(SchemaVersion, "V" + spec.replace(".", "_"))
    errors = JsonStrictValidator(version).validate_str(text)
    lib_version = pkg_version("cyclonedx-python-lib")
    return {
        "valid": errors is None,
        "validator": f"cyclonedx-python-lib {lib_version} JsonStrictValidator({spec})",
        "errors": None if errors is None else str(errors)[:2000],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--lock", required=True)
    ap.add_argument("--lock-diff-exit", type=int, default=None,
                    help="exit code of 'git diff --exit-code composer.json composer.lock'")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    text = Path(a.sbom).read_text(encoding="utf-8")
    sbom = json.loads(text)
    lock = json.loads(Path(a.lock).read_text(encoding="utf-8"))

    lock_prod, lock_dev = pairs_from_lock(lock)
    L = lock_prod | lock_dev
    S, S_dev = pairs_from_sbom(sbom)
    inter, union = S & L, S | L
    spec = sbom.get("specVersion", "1.5")

    result = {
        "spec_version": spec,
        "schema": validate_schema(text, spec),
        "lock_packages": len(L),
        "lock_packages_prod": len(lock_prod),
        "lock_packages_dev": len(lock_dev),
        "sbom_components": len(S),
        "intersection": len(inter),
        "completeness": round(len(inter) / len(L), 4) if L else None,
        "jaccard": round(len(inter) / len(union), 4) if union else None,
        "missing_from_sbom": sorted(f"{n}@{v}" for n, v in L - S),
        "extra_in_sbom": sorted(f"{n}@{v}" for n, v in S - L),
        "dev_flag_agreement": {
            "lock_dev_marked_dev_in_sbom": len(lock_dev & S_dev),
            "lock_dev_total": len(lock_dev),
            "prod_wrongly_marked_dev": sorted(f"{n}@{v}" for n, v in lock_prod & S_dev),
        },
        "lock_unchanged": None if a.lock_diff_exit is None else a.lock_diff_exit == 0,
    }
    Path(a.out).write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in ("sbom_components", "lock_packages", "completeness",
                                             "jaccard", "lock_unchanged")}))
    print("schema:", result["schema"])


if __name__ == "__main__":
    main()
