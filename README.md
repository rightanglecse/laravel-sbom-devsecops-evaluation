# SBOM-enabled DevSecOps pipeline for Laravel: evaluation artefacts

This repository contains the pipeline, benchmark, analysis scripts and raw results of the master's thesis

> **An SBOM-Enabled DevSecOps Pipeline for Vulnerability Management in Laravel Applications: Design and Evaluation Using a Seeded-Vulnerability Benchmark**
> Sheikh Md. Alim Ug Jaman Shajib, Masters in Cyber Security, Department of Computer Science and Engineering, World University of Bangladesh, 2026. Supervisor: Dr. Md Amran Hossen.

The case-study application itself is private and is not included. Everything needed to inspect or recompute the results reported in Chapter 5 of the thesis is here.

## Contents

| Folder | What it contains |
|--------|------------------|
| `pipeline/workflows/` | GitHub Actions workflows: `b0.yml` (functional baseline), `b1.yml` (report-only security baseline), `f.yml` (proposed framework), plus the workflows for runtime checks, gate scenarios, the Gitleaks re-run, the public applications and the timing experiment. Stored outside `.github/` so they do not run in this repository. |
| `pipeline/tools/` | Normaliser, four-state security gate, SBOM checker, step wrapper, run manifest, runtime check, gate-scenario builder and runner |
| `pipeline/security/` | Custom Laravel Semgrep rules, gate policy, exceptions, dependency evidence |
| `pipeline/seeds/manifest.csv` | Register of the 15 seeded vulnerabilities (class, CWE, file and lines, fix, runtime test) |
| `pipeline/tests/gate-scenarios/` | The ten report sets G1 to G10 used to test the gate |
| `pipeline/analysis/` | One script per hypothesis (H1 to H5), the C24 re-audit and `stats.py` (exact tests, Python standard library only) |
| `pipeline/docs/` | Pre-registration of hypotheses and thresholds; reproduction guide |
| `benchmark/` | Source of the seeded "clinic records" feature: `common/`, `vulnerable/` and `fixed/` variants with 15 runtime tests |
| `results/runs/` | Downloaded artefacts of every controlled run of 23 November 2026 (see `results/README.md`) |
| `results/analysis/` | Outputs of the analysis scripts and the two charts used in the thesis |
| `SHA256SUMS.txt` | SHA-256 checksum of every file, to show that nothing has been altered |

## Synthetic secrets

`benchmark/vulnerable/` contains **fake** credentials (Twilio and AWS formats) that exist only to test secret detection (seeds S11 and S12). They have never been valid for any service.

## Recomputing the results

Requirements: Python 3.10 or later; no third-party packages.

```bash
cd pipeline
python3 tools/run_gate_scenarios.py tests/gate-scenarios --out /tmp/h2.json            # H2: 10/10 scenarios
python3 tools/check_runtime.py --manifest seeds/manifest.csv \
  --vulnerable ../results/runs/03-runtime-vulnerable/benchmark-junit.xml \
  --fixed ../results/runs/04-runtime-fixed/benchmark-junit.xml --out /tmp/runtime.csv   # 15/15 seeds verified
python3 analysis/h1_sbom.py --subject onera-baseline=../results/runs/01-baseline-F \
  --subject firefly-iii=../results/runs/13-firefly --subject koel=../results/runs/14-koel --out /tmp/h1
python3 analysis/c24_reaudit.py --before ../results/runs/01-baseline-F --after ../results/runs/02-updated-F --out /tmp/c24
```

For H3, create a folder with `B0/`, `B1/` and `F/`, each holding `vulnerable/` and `fixed/` copies of runs 06 to 11, and run `analysis/h3_detection.py --results <folder>`. H4 uses `analysis/h4_triage.py` with run 01 and `results/runs/16-ratings-labels.csv`. H5 needs the GitHub API and was computed inside the timing workflow; its outputs are in `results/runs/15-timing/`.

## Verifying integrity

```bash
sha256sum -c SHA256SUMS.txt          # Linux / Git Bash
```

## Licence

Code (`pipeline/`, `benchmark/`): MIT licence (`LICENSE`). Results and documentation (`results/`, `pipeline/docs/`): Creative Commons Attribution 4.0 (`LICENSE-DATA`).

## Citation

See `CITATION.cff`, or cite the thesis and the archive DOI.
