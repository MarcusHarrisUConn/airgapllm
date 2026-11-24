# Read Entries from an Immutable JSONL Audit Log

Parses all entries in an `airgapllm` JSONL audit log into a structured
list with a companion summary `tibble`.

## Usage

``` r
audit_log_read(path)
```

## Arguments

- path:

  Character scalar path to the JSONL audit log file.

## Value

An S3 object of class `"airgap_audit_log"` containing `path`, `entries`
(list of parsed records), and `summary` (tibble).

## Examples

``` r
tmp_log <- tempfile(fileext = ".jsonl")
pf <- preflight_isolation_check(endpoint = "http://127.0.0.1:11434")
audit_log_append(tmp_log, pf)
#> <airgap_audit_entry> #1 [preflight_check]
#>   Run ID:       preflight_20261124T193322Z_48f35a71
#>   Timestamp:    2026-11-24T19:33:22Z
#>   Isolation:    PASS
#>   PII policy:   NA
#>   Prev hash:    GENESIS
#>   Entry hash:   sha256:dcd1f97513bf0dbddf47a7c310ae2b381328438c7b3a817124863de199164a99
audit_log_read(tmp_log)
#> <airgap_audit_log> (1 entries)
#>   Path: /tmp/RtmpYgqorT/file18221ee87c09.jsonl
#> # A tibble: 1 × 8
#>     seq timestamp       event_type run_id model_name isolation_status pii_policy
#>   <int> <chr>           <chr>      <chr>  <chr>      <chr>            <chr>     
#> 1     1 2026-11-24T19:… preflight… prefl… NA         PASS             NA        
#> # ℹ 1 more variable: entry_hash <chr>
unlink(tmp_log)
```
