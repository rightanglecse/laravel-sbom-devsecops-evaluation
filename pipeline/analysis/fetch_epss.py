#!/usr/bin/env python3
"""Fetch EPSS scores (FIRST.org API) for the CVEs in a triage rating sheet.

Usage: python3 analysis/fetch_epss.py triage/relevance-labels.csv triage/epss.csv
Run on a machine with internet access; the retrieval date is stored with each score.
"""
import csv
import json
import sys
import urllib.request

src, dst = sys.argv[1], sys.argv[2]
cves = sorted({r["cve"] for r in csv.DictReader(open(src)) if r.get("cve")})
rows = []
for i in range(0, len(cves), 50):
    url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 50])
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.load(resp)
    for d in data.get("data", []):
        rows.append({"cve": d["cve"], "epss": d["epss"], "percentile": d["percentile"], "date": d["date"]})
found = {r["cve"] for r in rows}
for c in cves:
    if c not in found:
        rows.append({"cve": c, "epss": "", "percentile": "", "date": "not in EPSS"})
with open(dst, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=["cve", "epss", "percentile", "date"])
    w.writeheader()
    w.writerows(rows)
print(f"{len(cves)} CVEs, {len(found)} with an EPSS score -> {dst}")
