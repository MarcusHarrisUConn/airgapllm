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
#>   Run ID:       preflight_20261124T214320Z_afdcfdfe
#>   Timestamp:    2026-11-24T21:43:20Z
#>   Isolation:    PASS
#>   PII policy:   NA
#>   Prev hash:    GENESIS
#>   Entry hash:   sha256:6e198d3e89a6ff7916f8d6551ada0ab3f81e247176e2d968bc87ce508841fa53
audit_log_read(tmp_log)
#> <airgap_audit_log> (1 entries)
#>   Path: /tmp/RtmpYwr7Bt/file1944152a5a05.jsonl
#> # A tibble: 1 × 8
#>     seq timestamp       event_type run_id model_name isolation_status pii_policy
#>   <int> <chr>           <chr>      <chr>  <chr>      <chr>            <chr>     
#> 1     1 2026-11-24T21:… preflight… prefl… NA         PASS             NA        
#> # ℹ 1 more variable: entry_hash <chr>
unlink(tmp_log)
```
