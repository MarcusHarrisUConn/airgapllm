## R CMD check results

Checked locally on macOS (`aarch64-apple-darwin23`, R 4.6.1):

- `rcmdcheck::rcmdcheck()` (full check including TinyTeX `pdflatex` PDF manual and all 5 vignettes): **0 errors | 0 warnings | 0 notes**
- `rcmdcheck::rcmdcheck(args = c("--as-cran"), env = c("_R_CHECK_CRAN_INCOMING_REMOTE_" = "false", "_R_CHECK_LIMIT_CORES_" = "true"))`: **0 errors | 0 warnings | 0 package notes** (only local macOS environment note: `/usr/bin/tidy` is legacy macOS tidy rather than HTML Tidy 5; all CRAN feasibility, Rd, example, test, vignette, LazyData, and PDF manual checks pass cleanly)
- `devtools::test()`: **1001 passed | 0 failed | 0 warnings | 0 skipped** across 10 test files (including permanent peer red-team regression suite `test-peer-redteam.R`)
- `covr::percent_coverage(covr::package_coverage())`: **94.31%**
- `spelling::spell_check_package()`: **0 misspellings**
- Source tarball size: **246.8 KB (0.241 MB)**

## CRAN Submission Notes

* This is the first CRAN submission of `airgapllm` (v0.5.0).
* All examples, unit tests, and 5 vignettes execute 100% offline using the built-in deterministic `runtime_mock()`, perform zero outbound network calls, write exclusively to `tempdir()` with explicit cleanup, respect `<= 2` CPU cores, and leave global state (`options()`, `par()`, `Sys.setenv()`, `.Random.seed`) unchanged.
* Bundled dataset `synthetic_notes` is 100% fictional and contains zero real personal or protected health information.
