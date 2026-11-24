#!/usr/bin/env bash
# Run one pipeline step, record its exit code and duration, never abort the job.
# Usage: tools/run_step.sh <name> <ok-exit-codes, e.g. 0,1> <command string>
# Writes reports/status/<name>.json; the gate uses it to detect crashed tools.
set -u
name="$1"; ok_codes="$2"; shift 2
mkdir -p reports/status
start=$(date +%s.%N)
bash -c "$*"
code=$?
end=$(date +%s.%N)
secs=$(python3 -c "print(round($end - $start, 2))")
python3 - "$name" "$ok_codes" "$code" "$secs" "$*" <<'PY'
import json, sys
name, ok, code, secs, cmd = sys.argv[1:]
json.dump({"name": name, "ok_codes": [int(x) for x in ok.split(",")], "exit_code": int(code),
           "seconds": float(secs), "command": cmd},
          open(f"reports/status/{name}.json", "w"), indent=2)
PY
echo "[$name] exit=$code (ok: $ok_codes) ${secs}s"
exit 0
