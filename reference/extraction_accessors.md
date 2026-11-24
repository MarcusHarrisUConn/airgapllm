# Access Run Provenance and Privacy Metadata from an `airgap_extraction`

Convenience accessors for the cryptographic run manifest, aggregate
privacy report, pre-flight isolation attestation, separate
pseudonymization vault, and throughput metrics attached to an
[`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
result.

## Usage

``` r
extraction_manifest(x)

extraction_privacy_report(x)

extraction_preflight(x)

extraction_vault(x)

extraction_throughput(x)
```

## Arguments

- x:

  An `airgap_extraction` tibble returned by
  [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md).

## Value

The requested provenance object (or `NULL` if not applicable, e.g.,
`extraction_vault()` when `pii_policy = "redact"`).

## Examples

``` r
df <- tibble::tibble(id = "R1", txt = "Dr. Jane Doe visited; mood calm.")
sc <- extraction_schema(mood = schema_field("enum", values = c("calm", "tense")))
res <- airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id")
extraction_throughput(res)
#> $rows_total
#> [1] 1
#> 
#> $rows_resumed
#> [1] 0
#> 
#> $rows_processed
#> [1] 1
#> 
#> $rows_succeeded
#> [1] 1
#> 
#> $rows_failed
#> [1] 0
#> 
#> $total_retries
#> [1] 0
#> 
#> $output_pii_leaks
#> [1] 0
#> 
#> $elapsed_sec
#> [1] 0.001
#> 
#> $rows_per_sec
#> [1] 1000
#> 
extraction_privacy_report(res)
#> <airgap_privacy_report> (aggregate counts only; zero raw PII)
#>   Documents scanned:  1
#>   Documents with PII: 1 (100%)
#>   Total detections:   1
#>   By entity type:
#>     - person_name: 1 (1 docs, 100%)
extraction_preflight(res)
#> <airgap_preflight> [PASS]
#>   Checked at:   2026-11-24T21:52:27Z
#>   Endpoint:     offline_mock
#>   Record hash:  sha256:4a82f733da4b54010047be56e16e80e6f96c17ccc72035a1865fdb6abe0fd4f4
#>   [PASS] endpoint_loopback_only: Built-in offline mock runtime.
#>   [PASS] model_digest_pinned: Model digest pinned in configuration (sha256:0000000000000000000000000000000000000000000000000000000000000000); pass `model_path` to verify file bytes.
#>   [PASS] env_proxy_isolation: No outbound proxy environment variables detected.
extraction_manifest(res)$schema_digest
#> [1] "sha256:00f5cbf251e9e3c279e18f1567b582d78751a6302bd85a449274a5c3025dc68b"
```
