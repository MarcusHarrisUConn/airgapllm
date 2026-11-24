# Estimate GPU VRAM Requirements for Local Open-Weights LLM Deployment

Estimates total GPU VRAM (in gigabytes) needed to serve a local
open-weights LLM under `Ollama`, `llama.cpp`, or `vLLM` as a function of
model parameter count (in billions), weight quantization (`Q4_K_M`,
`Q6_K`, `Q8_0`, `FP16`), context window length, concurrent batch size,
and KV-cache precision, helping research labs size lab workstations and
HPC GPU requests cleanly before launching air-gapped containers.

## Usage

``` r
estimate_vram_requirements(
  params_b,
  quantization = c("Q4_K_M", "Q6_K", "Q8_0", "FP16"),
  context_length = 4096L,
  batch_size = 1L,
  n_layers = NULL,
  kv_cache_quant = c("FP16", "Q8_0", "Q4_0"),
  overhead_gb = 1.2
)
```

## Arguments

- params_b:

  Positive numeric model parameter count in billions (e.g., `8` for
  Llama-3.1-8B, `14` for Qwen-2.5-14B, `70` for Llama-3.1-70B).

- quantization:

  Character scalar weight quantization format: `"Q4_K_M"` (default),
  `"Q6_K"`, `"Q8_0"`, or `"FP16"`.

- context_length:

  Positive integer sequence context window in tokens (default `4096L`).

- batch_size:

  Positive integer number of concurrent requests / batch sequences held
  in KV cache (default `1L`).

- n_layers:

  Optional positive integer transformer layer count. When `NULL`
  (default), inferred from typical GQA open-weights architectures scaled
  by `params_b`.

- kv_cache_quant:

  Character scalar KV-cache precision: `"FP16"` (default), `"Q8_0"`, or
  `"Q4_0"`.

- overhead_gb:

  Non-negative numeric framework/CUDA/activation memory overhead in GB
  (default `1.2`).

## Value

An S3 object of class `"airgap_vram_estimate"` with `params_b`,
`quantization`, `context_length`, `batch_size`, `kv_cache_quant`,
`weights_gb`, `kv_cache_gb`, `overhead_gb`, `total_vram_gb`,
`recommended_gpu_tier`, and `fits_tiers` (tibble).

## Examples

``` r
estimate_vram_requirements(8, quantization = "Q4_K_M", context_length = 8192L)
#> <airgap_vram_estimate>
#>   Model:            8B parameters (Q4_K_M, 32 layers)
#>   Context / Batch:  8192 tokens x 1 (KV: FP16)
#>   Weights VRAM:     4.47 GB
#>   KV-Cache VRAM:    1.00 GB
#>   Runtime Overhead: 1.20 GB
#>   Total Estimated:  6.67 GB
#>   Recommended Tier: 8 GB (Workstation RTX 4060 / 16 GB Unified)
estimate_vram_requirements(70, quantization = "Q4_K_M", context_length = 4096L, batch_size = 4L)
#> <airgap_vram_estimate>
#>   Model:            70B parameters (Q4_K_M, 80 layers)
#>   Context / Batch:  4096 tokens x 4 (KV: FP16)
#>   Weights VRAM:     39.12 GB
#>   KV-Cache VRAM:    5.00 GB
#>   Runtime Overhead: 1.65 GB
#>   Total Estimated:  45.77 GB
#>   Recommended Tier: 48 GB (L40S / A6000)
```
