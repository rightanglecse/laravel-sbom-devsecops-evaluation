# Controlled runs (23 November 2026, runner image ubuntu-24.04 / 20261116)

| Folder | Purpose | Workflow | Branch | Commit | Run ID |
|--------|---------|----------|--------|--------|--------|
| 01-baseline-F | Baseline state (H1, H4, C24) | f.yml | main | 4129b73 | 45199033665 |
| 02-updated-F | After dependency update (C24) | f.yml | main | 2e74f3a | 45203176999 |
| 03-runtime-vulnerable | Runtime check of the seeds | seed-runtime.yml | bench-vulnerable | c8e992b | |
| 04-runtime-fixed | Runtime check of the fixes | seed-runtime.yml | bench-fixed | bf174a7 | |
| 05-gate-scenarios | Gate scenarios G1-G10 (H2) | gate-scenarios.yml | main | f439e97 | |
| 06-B0-vulnerable | Detection (H3) | b0.yml | bench-vulnerable | c8e992b | 45219187076 |
| 07-B0-fixed | Detection (H3) | b0.yml | bench-fixed | bf174a7 | 45219251565 |
| 08-B1-vulnerable | Detection (H3) | b1.yml | bench-vulnerable | c8e992b | 45219696235 |
| 09-B1-fixed | Detection (H3) | b1.yml | bench-fixed | bf174a7 | 45219720135 |
| 10-F-vulnerable | Detection and gate (H2, H3) | f.yml | bench-vulnerable | c8e992b | 45221186374 |
| 11-F-fixed | Detection and gate (H2, H3) | f.yml | bench-fixed | bf174a7 | 45221217366 |
| 12-gitleaks | Gitleaks re-run on 4b74bfa and 2bfcfae (C21) | gitleaks-rerun.yml | main | f439e97 | |
| 13-firefly | SBOM check, Firefly III v6.7.9 (H1) | h1-secondary.yml | main | f439e97 | 45224353379 |
| 14-koel | SBOM check, Koel v9.15.0 (H1) | h1-secondary.yml | main | f439e97 | 45224506962 |
| 15-timing | Timing experiment, 39 counted runs (H5) | timing-driver.yml | timing | f439e97 | see runs.csv |
| 16-ratings | Two-rater relevance labels for the 35 baseline advisories (H4) | | | | |

Each F folder contains the raw reports, `status/` (exit code of every tool), `versions/`, `run-manifest-F.json` and `gate-decision.json`.
The old workflow (devsecops.yml) on bench-vulnerable is run #17, ID 45218463147: it reported six Gitleaks findings and finished with success.
In `12-gitleaks`, the author's e-mail address has been replaced with `[redacted]`.
