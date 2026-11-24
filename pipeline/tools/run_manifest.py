#!/usr/bin/env python3
"""Write reports/run-manifest-<config>.json: commit, lock-file hash, runner image,
run id and the version of every tool that ran (read from reports/versions/*.txt).

Usage: python3 tools/run_manifest.py <B0|B1|F> <warm|cold>
"""
import hashlib
import json
import os
import sys
from pathlib import Path

config, cache = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "warm"
lock = Path("composer.lock")
versions = {}
for f in sorted(Path("reports/versions").glob("*.txt")):
    versions[f.stem] = f.read_text(errors="replace").strip().splitlines()[:2]
manifest = {
    "config": config,
    "cache": cache,
    "commit": os.environ.get("GITHUB_SHA"),
    "ref": os.environ.get("GITHUB_REF_NAME"),
    "run_id": os.environ.get("GITHUB_RUN_ID"),
    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "workflow": os.environ.get("GITHUB_WORKFLOW"),
    "runner_image": f"{os.environ.get('ImageOS')} {os.environ.get('ImageVersion')}",
    "composer_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else None,
    "tool_versions": versions,
}
Path("reports").mkdir(exist_ok=True)
Path(f"reports/run-manifest-{config}.json").write_text(json.dumps(manifest, indent=2))
print(json.dumps(manifest, indent=2))
