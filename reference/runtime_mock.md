# Configure a Deterministic Offline Mock Runtime

Provides a fully offline, deterministic local runtime for dry-runs,
reproducible vignettes, and unit testing without a GPU or running
container. Supports custom extraction handlers, deterministic
malformed-JSON injection to exercise structured repair retries
(`malform_schedule`), unrecoverable row failures (`fail_rows`), and
simulated mid-batch crashes (`crash_after`) to test crash-resumable
checkpointing.

## Usage

``` r
runtime_mock(
  handler = NULL,
  model = "mock-llama-3.1-8b-instruct-q4",
  temperature = 0,
  seed = 42L,
  top_p = 1,
  max_tokens = 1024L,
  malform_schedule = list(),
  fail_rows = character(),
  crash_after = NULL,
  container_spec = NULL,
  model_digest = paste0("sha256:", strrep("0", 64L))
)
```

## Arguments

- handler:

  Optional function with signature
  `function(prompt, row_id, attempt, schema)` returning either a JSON
  string or a named list (automatically serialized to JSON). When
  `NULL`, generates deterministic schema-conformant JSON keyed by
  `(seed, row_id)`.

- model:

  Character scalar mock model label.

- temperature:

  Numeric simulated temperature (default `0`).

- seed:

  Integer deterministic seed (default `42L`).

- top_p:

  Numeric simulated `top_p` (default `1`).

- max_tokens:

  Integer simulated `max_tokens` (default `1024L`).

- malform_schedule:

  Optional named list mapping `row_id` (as character) to a character
  vector of malformed raw outputs returned on attempts 1, 2, etc.,
  before falling back to valid generation on subsequent repair retries.

- fail_rows:

  Optional character vector of `row_id`s that always return invalid
  output on every attempt.

- crash_after:

  Optional positive integer count of newly processed rows after which
  the mock runtime throws an `airgap_simulated_crash` error to simulate
  mid-batch interruption.

- container_spec:

  Optional
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md).

- model_digest:

  Optional pinned SHA-256 digest (defaults to a deterministic
  placeholder digest).

## Value

An S3 object of class `c("airgap_runtime_mock", "airgap_runtime")`.

## Examples

``` r
rt <- runtime_mock(seed = 123L)
print(rt)
#> <airgap_runtime:mock>
#>   Model:       mock-llama-3.1-8b-instruct-q4
#>   Endpoint:    mock://offline (offline_mock)
#>   Temperature: 0 | Seed: 123
#>   Model SHA:   sha256:0000000000000000000000000000000000000000000000000000000000000000
```
