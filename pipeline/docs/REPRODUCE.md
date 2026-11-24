# Reproducing the evaluation

This repository contains the pipeline, the benchmark manifest, the gate and the analysis
scripts used in the thesis "An SBOM-Enabled DevSecOps Pipeline for Vulnerability Management in
Laravel Applications: Design and Evaluation Using a Seeded-Vulnerability Benchmark".

## Layout

| Path | Content |
|------|---------|
| `.github/workflows/b0.yml`, `b1.yml`, `f.yml` | The three compared configurations |
| `.github/workflows/seed-runtime.yml` | Runtime tests that prove each seed is exploitable |
| `.github/workflows/gate-scenarios.yml` | Gate acceptance scenarios G1–G10 |
| `tools/normalise.py`, `tools/gate.py` | Normaliser and four-state security gate (exit 0/1/2/3) |
| `tools/sbom_check.py` | SBOM schema validation, completeness and Jaccard against composer.lock |
| `security/` | Custom Semgrep rules, gate policy, exceptions, dependency evidence |
| `seeds/manifest.csv` | Seed register (no labels in application code) |
| `tests/gate-scenarios/` | Report sets for G1–G10 |
| `analysis/` | H1–H5 analysis scripts (Python standard library only) |
| `docs/PREREGISTRATION.md` | Hypotheses and thresholds, committed before the runs |

## Re-running

Requirements: GitHub CLI (`gh auth login`), Python 3.10+.

1. Run a workflow: `gh workflow run f.yml --ref <branch>`.
2. Download its reports: `bash analysis/fetch_run.sh <run-id> 'reports-F-*' results/<folder>`.
3. Run the analysis for a hypothesis, for example
   `python3 analysis/h3_detection.py --results results/detection --out results/h3`.

The gate can be run locally on any downloaded report folder:

```bash
python3 tools/gate.py --reports results/detection/F/vulnerable --out /tmp/gate.json; echo "exit $?"
python3 tools/run_gate_scenarios.py tests/gate-scenarios --out /tmp/scenarios.json
```
