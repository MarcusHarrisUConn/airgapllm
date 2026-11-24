# Configure a Local Air-Gapped Ollama Runtime

Creates a runtime backend targeting a strictly local loopback Ollama
server (`/api/chat`). Rejects any non-loopback host URL at construction
time and disables all outbound HTTP proxies (`noproxy = "*"`) on every
request.

## Usage

``` r
runtime_ollama(
  model,
  host = "http://127.0.0.1:11434",
  temperature = 0,
  seed = 42L,
  top_p = 1,
  num_ctx = 4096L,
  num_predict = 1024L,
  timeout = 120,
  container_spec = NULL,
  model_digest = NULL,
  transport = NULL
)
```

## Arguments

- model:

  Character scalar Ollama model name/tag (e.g.,
  `"llama3.1:8b-instruct-q4_K_M"`).

- host:

  Character scalar loopback URL (default `"http://127.0.0.1:11434"`).
  Non-loopback hosts trigger an immediate `airgap_isolation_error`.

- temperature:

  Numeric decoding temperature (default `0` for determinism).

- seed:

  Integer random seed passed to Ollama (default `42L`).

- top_p:

  Numeric nucleus sampling parameter (default `1`).

- num_ctx:

  Integer context window size (default `4096L`).

- num_predict:

  Integer maximum generated tokens (default `1024L`).

- timeout:

  Numeric per-request timeout in seconds (default `120`).

- container_spec:

  Optional
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md)
  associated with this runtime.

- model_digest:

  Optional pinned SHA-256 digest of the model weights.

- transport:

  Optional custom `httr2` mock transport function
  `function(req) httr2::response(...)` for offline HTTP testing.

## Value

An S3 object of class `c("airgap_runtime_ollama", "airgap_runtime")`.

## Examples

``` r
rt <- runtime_ollama("llama3.1:8b-instruct-q4_K_M")
print(rt)
#> <airgap_runtime:ollama>
#>   Model:       llama3.1:8b-instruct-q4_K_M
#>   Endpoint:    http://127.0.0.1:11434 (loopback)
#>   Temperature: 0 | Seed: 42
```
