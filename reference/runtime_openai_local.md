# Configure a Local Air-Gapped OpenAI-Compatible Runtime (`llama.cpp` / `vLLM`)

Creates a runtime backend targeting a strictly local loopback
OpenAI-compatible server (`/chat/completions`), such as `llama-server`
(`llama.cpp`) or `vLLM`. Strictly rejects any non-loopback remote URL
(such as external cloud APIs or LAN hosts) and disables HTTP proxies on
every request.

## Usage

``` r
runtime_openai_local(
  model,
  base_url = "http://127.0.0.1:8000/v1",
  api_key = "airgap-local",
  temperature = 0,
  seed = 42L,
  top_p = 1,
  max_tokens = 1024L,
  timeout = 120,
  container_spec = NULL,
  model_digest = NULL,
  transport = NULL
)
```

## Arguments

- model:

  Character scalar local model identifier served by `llama.cpp` or
  `vLLM`.

- base_url:

  Character scalar loopback base URL (default
  `"http://127.0.0.1:8000/v1"`). Non-loopback URLs trigger an immediate
  `airgap_isolation_error`.

- api_key:

  Local dummy bearer token (default `"airgap-local"`).

- temperature:

  Numeric decoding temperature (default `0`).

- seed:

  Integer random seed (default `42L`).

- top_p:

  Numeric nucleus sampling parameter (default `1`).

- max_tokens:

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

  Optional custom `httr2` mock transport function for offline HTTP
  testing.

## Value

An S3 object of class
`c("airgap_runtime_openai_local", "airgap_runtime")`.

## Examples

``` r
rt <- runtime_openai_local("qwen2.5-7b-instruct", base_url = "http://127.0.0.1:8080/v1")
print(rt)
#> <airgap_runtime:openai_local>
#>   Model:       qwen2.5-7b-instruct
#>   Endpoint:    http://127.0.0.1:8080/v1 (loopback)
#>   Temperature: 0 | Seed: 42
```
