# Recommend Optimal Local LLM Configuration for Workstation or HPC Hardware

Computes hardware-aware local model sizing, quantization, context
window, concurrency (`batch_size`), KV-cache precision, and hardened
container memory limits given available GPU VRAM, host RAM, GPU count,
corpus size, and average document length. Evaluates open-weights
parameter tiers (`3B`, `8B`, `14B`, `32B`, `70B`) against
[`estimate_vram_requirements()`](https://marcusharrisphd.com/airgapllm/reference/estimate_vram_requirements.md)
so research labs avoid GPU out-of-memory failures on lab workstations
and HPC Slurm nodes.

## Usage

``` r
recommend_runtime_config(
  vram_gb,
  ram_gb = 32,
  n_gpus = 1L,
  n_docs = 1000L,
  avg_tokens = 800L,
  priority = c("balanced", "accuracy", "throughput"),
  backend = c("ollama", "llama.cpp", "vllm"),
  safety_margin = 0.88
)
```

## Arguments

- vram_gb:

  Non-negative numeric VRAM per GPU in gigabytes (e.g., `16`, `24`,
  `48`, `80`; pass `0` for CPU-only workstations).

- ram_gb:

  Positive numeric host system RAM in gigabytes (default `32`).

- n_gpus:

  Positive integer number of GPUs allocated (default `1L`).

- n_docs:

  Positive integer expected corpus row count (default `1000L`).

- avg_tokens:

  Positive integer average tokens per input document (default `800L`).

- priority:

  Optimization goal: `"balanced"` (default), `"accuracy"` (favors larger
  parameter count and higher precision), or `"throughput"` (favors
  higher concurrent batching and faster quantized weights).

- backend:

  Target local container runtime: `"ollama"` (default), `"llama.cpp"`,
  or `"vllm"`.

- safety_margin:

  Numeric VRAM utilization ceiling in `(0.5, 0.98]` to leave headroom
  against CUDA fragmentation (default `0.88`).

## Value

An S3 object of class `"airgap_runtime_recommendation"` containing
`hardware`, `workload`, `recommended` (list of optimal settings and
container memory limits), `vram_estimate` (`airgap_vram_estimate`),
`candidates` (ranked feasible tibble), and `rationale` (character
vector).

## Examples

``` r
recommend_runtime_config(vram_gb = 24, ram_gb = 64, n_docs = 5000L, avg_tokens = 1200L)
#> <airgap_runtime_recommendation> [backend=ollama, priority=balanced]
#>   Hardware:        1x 24 GB GPU (24 GB total) | 64 GB RAM
#>   Recommended:     14B open-weights (Q8_0)
#>   Context / Batch: 4096 tokens | batch_size=4 | KV=FP16
#>   Est. Memory:     18.10 GB (75.4% utilization)
#>   Container Spec:  gpu='nvidia', memory_limit='27g', shm_size='2g'
recommend_runtime_config(vram_gb = 80, n_gpus = 2L, priority = "accuracy", backend = "vllm")
#> <airgap_runtime_recommendation> [backend=vllm, priority=accuracy]
#>   Hardware:        2x 80 GB GPU (160 GB total) | 32 GB RAM
#>   Recommended:     70B open-weights (FP16)
#>   Context / Batch: 4096 tokens | batch_size=4 | KV=FP16
#>   Est. Memory:     137.04 GB (85.7% utilization)
#>   Container Spec:  gpu='nvidia', memory_limit='24g', shm_size='6g', TP=2
```
