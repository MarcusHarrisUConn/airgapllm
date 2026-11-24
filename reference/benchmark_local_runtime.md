# Benchmark Throughput, Latency Quantiles, and Retry Rate on a Local Runtime

Runs a controlled offline pilot benchmark of
[`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
on a sample of rows (supplied via `data` or generated synthetically when
`data = NULL`) using any local or mock runtime, reporting throughput
(`rows_per_sec`), estimated full-corpus ETA, schema validation success
rate, repair retry rate, and per-row latency quantiles (`min`, `p50`,
`mean`, `p95`, `max` in milliseconds). Never stores or prints raw
participant text.

## Usage

``` r
benchmark_local_runtime(
  runtime,
  schema,
  data = NULL,
  text_col = NULL,
  n_sample = 10L,
  corpus_size = NULL,
  pii_policy = c("redact", "verified_deidentified"),
  pii_config = NULL,
  max_retries = 2L,
  prompt_template = NULL,
  container_spec = NULL
)
```

## Arguments

- runtime:

  An `airgap_runtime` object from
  [`runtime_ollama()`](https://marcusharrisphd.com/airgapllm/reference/runtime_ollama.md),
  [`runtime_openai_local()`](https://marcusharrisphd.com/airgapllm/reference/runtime_openai_local.md),
  or
  [`runtime_mock()`](https://marcusharrisphd.com/airgapllm/reference/runtime_mock.md).

- schema:

  An
  [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md)
  object.

- data:

  Optional data frame containing sample text rows. If `NULL`,
  synthesizes deterministic synthetic clinical benchmark sentences.

- text_col:

  Character scalar text column name (required when `data` is supplied).

- n_sample:

  Positive integer number of rows to benchmark (default `10L`). When
  `data` has fewer than `n_sample` rows, benchmarks all rows of `data`.

- corpus_size:

  Optional positive integer target full-corpus size used to project
  estimated runtime ETA. Defaults to `nrow(data)` when `data` is
  supplied, or `1000L` otherwise.

- pii_policy:

  Pre-inference privacy policy: `"redact"` (default) or
  `"verified_deidentified"`.

- pii_config:

  Optional
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  object.

- max_retries:

  Non-negative integer maximum structured repair retries per row
  (default `2L`).

- prompt_template:

  Optional prompt template override.

- container_spec:

  Optional
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md).

## Value

An S3 object of class `"airgap_benchmark"` containing `model`,
`backend_type`, `n_sample`, `rows_succeeded`, `rows_failed`,
`success_rate_pct`, `total_retries`, `repair_retry_rate_pct`,
`elapsed_sec`, `rows_per_sec`, `latency_ms` (list of `min`, `p50`,
`mean`, `p95`, `max`), `corpus_size`, `estimated_eta_sec`,
`estimated_eta_formatted`, and `benchmarked_at`.

## Examples

``` r
sc <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L)
)
bm <- benchmark_local_runtime(runtime_mock(seed = 42L), sc, n_sample = 6L, corpus_size = 5000L)
bm
#> <airgap_benchmark> [mock | mock-llama-3.1-8b-instruct-q4]
#>   Sample rows:     6 (succeeded=6 [100%], failed=0)
#>   Repair retries:  0 total (0% of rows retried)
#>   Throughput:      500.00 rows/sec (elapsed=0.012s)
#>   Latency (ms):    p50=1 | p95=1 | mean=0.67 (range 0-1)
#>   Projected ETA:   10.0 sec for 5000 rows
```
