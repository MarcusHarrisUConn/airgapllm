# Verify Cryptographic Integrity and Zero-PII Invariants of an Audit Log

Recomputes the SHA-256 hash chain from `GENESIS` through the final entry
in a JSONL audit log, verifying sequence continuity (`1..n`),
`prev_hash` links, exact `entry_hash` digests, and absence of forbidden
raw-text keys. Detects field edits, deletions, insertions, line
reordering, and truncation.

## Usage

``` r
audit_log_verify(path, strict = TRUE)
```

## Arguments

- path:

  Character scalar path to the JSONL audit log file.

- strict:

  Logical scalar; if `TRUE` (default), also verifies that all top-level
  fields belong to the strict v1.0 audit schema allowlist.

## Value

An S3 object of class `"airgap_audit_verification"` with elements
`valid`, `n_entries`, `first_invalid_seq`, `chain_head_hash`, `issues`,
and `verified_at`.

## Examples

``` r
tmp_log <- tempfile(fileext = ".jsonl")
pf <- preflight_isolation_check(endpoint = "http://127.0.0.1:11434")
audit_log_append(tmp_log, pf)
#> <airgap_audit_entry> #1 [preflight_check]
#>   Run ID:       preflight_20261124T210603Z_45740cab
#>   Timestamp:    2026-11-24T21:06:03Z
#>   Isolation:    PASS
#>   PII policy:   NA
#>   Prev hash:    GENESIS
#>   Entry hash:   sha256:4ed9eec4d36d0c169abf0115ed38c30795c7f2dbb3d68f1f6d8b556684a5013f
audit_log_verify(tmp_log)
#> <airgap_audit_verification> [VALID]
#>   Entries verified: 1
#>   Chain head hash:  sha256:4ed9eec4d36d0c169abf0115ed38c30795c7f2dbb3d68f1f6d8b556684a5013f
unlink(tmp_log)
```
