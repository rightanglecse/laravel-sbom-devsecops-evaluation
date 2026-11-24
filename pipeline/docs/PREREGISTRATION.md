# Pre-registration of hypotheses, thresholds and analysis rules

Commit this file **before** any controlled run (B0/B1/F detection, gate scenarios, timing).
The commit date is the evidence that the thresholds were not chosen after seeing results
(supervisor comment C4). Do not edit it afterwards; add a dated note at the bottom instead.

- Author: Sheikh Md. Alim Ug Jaman Shajib (ID 26240324)
- Committed on: 2026-11-23 (fill in, then commit)
- Repository commit of the clean control: 2e74f3a (fill in after Step 2 of the runbook)

## 1. Hypotheses and thresholds

| H | Statement | Supported only if |
|---|-----------|-------------------|
| H1 | The SBOM produced in CI is valid and complete relative to composer.lock, and SBOM-based matching reproduces Composer audit. | CycloneDX 1.5 schema valid; completeness = 1.00; Jaccard ≥ 0.90; OSV-Scanner run on the SBOM reproduces ≥ 90% of Composer advisory records (matched by CVE or GHSA alias and package); composer.json/composer.lock unchanged during the run. |
| H2 | The gate returns the expected decision in every predefined scenario; the report-only workflow blocks none. | Gate correct in 10/10 scenarios G1–G10 (≥ 8 required); the legacy workflow concludes "success" in every scenario it is run on. |
| H3 | F detects more seeds than B1, and B1 more than B0, at acceptable precision. | Recall(F) ≥ 0.60; Precision(F) ≥ 0.70; Recall(F) > Recall(B1) and Recall(B1) > Recall(B0), each with exact McNemar p < 0.05 (two-sided). |
| H4 | Rule-based triage shrinks the immediate-review queue without losing relevant advisories. | Queue reduction ≥ 30% versus CVSS-only ordering (medium or higher); 100% of advisories with final label "relevant" stay in Fix-now or Review; Cohen's κ between the two raters ≥ 0.60. |
| H5 | F adds an acceptable amount of pipeline time. | Median wall-clock time of F (warm cache, 10 runs) minus that of B0 ≤ 90 s. Reported with IQR; Mann–Whitney U (exact, two-sided). |

Null hypotheses: the negation of each row. Significance level α = 0.05 throughout.

**Classification rule.** A hypothesis is *supported* if every condition in its row holds,
*not supported* if any condition fails, and *inconclusive* only if the data needed for a
condition could not be produced (for example a tool could not run). Confidence intervals are
reported for every proportion but do not by themselves make a result inconclusive.

## 2. Benchmark (H3)

- 15 seeds, 7 classes (SQL injection ×3, XSS ×3, mass assignment ×2, broken access control ×2,
  hard-coded secret ×2, CSRF exclusion ×1, debug information exposure ×1, path traversal ×1),
  listed in `seeds/manifest.csv`. No seed is labelled in application code.
- Every seed has a fixed counterpart (branch `bench-fixed`) and a runtime test. A seed is kept only
  if its test passes on `bench-vulnerable` and fails on `bench-fixed` (`tools/check_runtime.py`).
- Clean control: the application without the benchmark feature (`main` after the dependency update).
- **True positive:** a finding of an allowed tool in a seed file within the seed's line range ± 2 lines.
- **False positive:** every Semgrep, Psalm or Gitleaks finding on `bench-fixed`, plus any such finding
  on `bench-vulnerable` inside a benchmark file that matches no seed. Each candidate is checked by hand;
  a candidate that is a real problem in pre-existing application code is reported separately and not
  counted as FP. PHPStan findings can earn a TP but are never counted as FP (PHPStan is not a
  security tool).
- Tools per configuration: B0 = PHPStan (level 5); B1 = PHPStan, Composer audit, Gitleaks, Semgrep p/php;
  F = B1 + Semgrep custom Laravel rules (`security/semgrep-laravel.yml`), Psalm taint analysis,
  CycloneDX SBOM, OSV-Scanner, triage and gate.

## 3. Triage rules (H2, H4) - applied in order

| Rule | Condition | Outcome |
|------|-----------|---------|
| T1 | Dependency advisory with no severity, unknown dev/prod scope or unknown fix status | Review |
| T2 | Development-only package (SBOM `isDevRequirement`) and no recorded production use | Defer |
| T3 | Direct dependency, fixed version available, severity high or critical; or any Gitleaks secret; or a Semgrep finding of level *error* / a Psalm `Tainted*` finding | Fix now (block) |
| T4 | Package recorded as on a user-input path, or input-path evidence missing; Semgrep level *warning* | Review |
| T5 | Recorded evidence that the package is not on a user-input path | Defer (scheduled update) |

Gate decision precedence: Incomplete (missing/empty/malformed report or tool error) > Block > Review > Pass.
Approved exceptions need owner, reason and expiry date (`security/exceptions.json`).
CVSS-only comparator: every advisory labelled medium, high or critical is queued.
EPSS is reported only for advisories with a CVE, with n stated.

## 4. Timing (H5)

Same commit (branch `timing`), runner image `ubuntu-24.04`, tools pinned as in the workflow `env` blocks.
One unmeasured priming run per configuration, then 10 warm runs interleaved B0, B1, F, then 3 cold runs
each (Composer cache disabled). Duration = first job start to last job completion (queue time excluded).

## 5. Changes relative to the thesis draft of 26 October 2026 (made before any controlled run)

1. Triage rule T5 added; draft rule T4 would have sent every transitive advisory to Review,
   making a queue reduction impossible by construction.
2. Classification rule clarified (Section 1); the draft rule made any result with a wide
   confidence interval "inconclusive".
3. Secondary open-source applications are used for H1 only, not H5.
4. Gate configuration files are JSON (`policy.json`, `exceptions.json`, `dependency-evidence.json`).
5. Seed S14 is debug information returned by an error handler controlled by a committed
   configuration flag (instead of forcing APP_DEBUG), because APP_DEBUG is overridden by the
   environment in CI and could not be tested reliably.
6. B0 uses PHPStan only (Larastan is not installed in the case application).

## 6. Notes added after commit (dated)

- YYYY-MM-DD: seed set frozen at commit ______ after runtime verification (__/15 verified).
