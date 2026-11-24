# Append a Tamper-Evident Entry to an Immutable JSONL Audit Log

Writes a cryptographically hash-chained audit record
(`prev_hash -> entry_hash`) to a JSONL audit log file. Enforces strict
zero-PII-leakage invariants by rejecting raw text keys, undeclared
top-level fields, non-integer PII summaries, and any metadata strings
containing detectable PII.

## Usage

``` r
audit_log_append(
  path,
  entry,
  event_type = "extraction_run",
  metadata = NULL,
  verify_existing = TRUE
)
```

## Arguments

- path:

  Character scalar path to the JSONL audit log file.

- entry:

  An `airgap_extraction` result, `airgap_run_manifest`,
  `airgap_preflight`, `airgap_digest_verification`, or validated named
  list matching the v1.0 audit schema.

- event_type:

  Character scalar event label (default `"extraction_run"`).

- metadata:

  Optional named list of non-sensitive study metadata (e.g.,
  `list(irb_protocol = "IRB-2026-0412", site = "Site-A")`). Scanned for
  PII and length-capped at 256 characters per string.

- verify_existing:

  Logical scalar; if `TRUE` (default) and `path` already exists,
  verifies the existing hash chain via
  [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md)
  before appending.

## Value

An S3 object of class `"airgap_audit_entry"` representing the appended
record (including `seq`, `prev_hash`, and `entry_hash`).

## Examples

``` r
tmp_log <- tempfile(fileext = ".jsonl")
df <- tibble::tibble(id = "R1", text = "Patient John Doe emailed john@clinic.org.")
sc <- extraction_schema(flag = schema_field("logical"))
res <- airgap_extract(df, "text", sc, runtime_mock(), id_col = "id")
entry <- audit_log_append(tmp_log, res)
audit_log_verify(tmp_log)
#> <airgap_audit_verification> [VALID]
#>   Entries verified: 1
#>   Chain head hash:  sha256:facf923c0f1b9b3db2d1f0ebc5cb5ce9bfb5626b3d4db286b4aa2e10f45f9efa
unlink(tmp_log)
```
