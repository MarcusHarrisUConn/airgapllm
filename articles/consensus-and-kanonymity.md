# Multi-Pass Consensus Extraction, k-Anonymity Export Checks, and Local Hardware Sizing

## Overview

Once a research lab has verified offline network isolation and scrubbed
direct identifiers under HIPAA Safe Harbor, three practical questions
remain before running production extractions and sharing derived tables
with collaborators:

1.  **How reliable are local 7B–14B open-weights extractions across
    seeds and prompt phrasings?** Use
    [`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md)
    to execute crossed multi-pass self-consistency runs and inspect
    per-row agreement and long-format pass reliability data.
2.  **Could indirect quasi-identifiers (`site`, `age_band`, `wave`,
    `zip3`) re-identify individuals in an exported analytic table?**
    Audit tables with
    [`assess_reidentification_risk()`](https://marcusharrisphd.com/airgapllm/reference/assess_reidentification_risk.md)
    and enforce $`k`$-anonymity and $`l`$-diversity with
    [`apply_k_anonymity()`](https://marcusharrisphd.com/airgapllm/reference/apply_k_anonymity.md).
3.  **Which quantization, context window, and batch size best fit our
    lab GPU or HPC allocation—and how long will 10,000 rows take?** Size
    hardware with
    [`recommend_runtime_config()`](https://marcusharrisphd.com/airgapllm/reference/recommend_runtime_config.md)
    and measure real pilot throughput with
    [`benchmark_local_runtime()`](https://marcusharrisphd.com/airgapllm/reference/benchmark_local_runtime.md).

``` r

library(airgapllm)
library(tibble)
data("synthetic_notes", package = "airgapllm")
```

## 1. Multi-Pass Self-Consistency & Consensus Extraction

Local quantized models can exhibit occasional stochastic or
prompt-framing sensitivity on borderline clinical notes.
[`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md)
runs a deterministic grid of random `seeds` and/or `prompt_templates`
over the already-sanitized corpus, aggregating categorical/logical
fields by majority vote and numeric/integer fields by median or trimmed
mean:

``` r

clinical_schema <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L),
  crisis_flag = schema_field("logical"),
  name = "consensus_coding_v1"
)

prompts <- c(
  concise = "Classify sentiment, severity (0-10), and crisis_flag from this record:\n{text}",
  clinical = "As a clinical rater, return strict JSON coding for this note:\n{text}"
)

work_dir <- tempfile("airgap_v04_")
dir.create(work_dir)
audit_file <- file.path(work_dir, "consensus_audit.jsonl")

# 2 prompts x 2 seeds = 4 crossed passes per document
cons_res <- airgap_extract_consensus(
  data = synthetic_notes[1:6, ],
  text_col = "note_text",
  schema = clinical_schema,
  runtime = runtime_mock(model = "llama3.1:8b-instruct-q4_K_M", seed = 100L),
  seeds = c(100L, 200L),
  prompt_templates = prompts,
  id_col = "note_id",
  numeric_agg = "median",
  tie_policy = "first",
  audit_log_path = audit_file
)

cons_res
#> # A tibble: 6 × 8
#>   note_id sentiment severity crisis_flag .agreement .passes_ok .passes_total
#>   <chr>   <chr>        <int> <lgl>            <dbl>      <int>         <int>
#> 1 SYN_001 positive         8 TRUE             0.7            4             4
#> 2 SYN_002 positive         2 FALSE            0.633          4             4
#> 3 SYN_003 neutral          2 FALSE            0.617          4             4
#> 4 SYN_004 negative         5 TRUE             0.55           4             4
#> 5 SYN_005 negative         2 TRUE             0.783          4             4
#> 6 SYN_006 negative         4 TRUE             0.65           4             4
#> # ℹ 1 more variable: .status <chr>
```

Inspect field-level consensus diagnostics and the long-format pass table
(`unit_id`, `pass_id`, `prompt_id`, `seed`, plus all typed schema
columns), which is directly structured for multi-facet psychometric
reliability modeling (such as Generalizability Theory / G-studies; when
loading alongside other LLM evaluation packages that also export
[`schema_field()`](https://marcusharrisphd.com/airgapllm/reference/schema_field.md),
qualify calls as
[`airgapllm::schema_field()`](https://marcusharrisphd.com/airgapllm/reference/schema_field.md)):

``` r

consensus_diagnostics(cons_res)
#> # A tibble: 3 × 6
#>   field       type    n_valid_rows mean_agreement pct_unanimous n_ties
#>   <chr>       <chr>          <int>          <dbl>         <dbl>  <int>
#> 1 sentiment   enum               6          0.625             0      1
#> 2 severity    integer            6          0.717             0      0
#> 3 crisis_flag logical            6          0.625             0      3
head(consensus_passes(cons_res), 8L)
#> # A tibble: 8 × 9
#>   unit_id pass_id prompt_id  seed sentiment severity crisis_flag .status
#>   <chr>   <chr>   <chr>     <int> <chr>        <int> <lgl>       <chr>  
#> 1 SYN_001 pass_01 concise     100 positive         8 TRUE        ok     
#> 2 SYN_002 pass_01 concise     100 positive         0 FALSE       ok     
#> 3 SYN_003 pass_01 concise     100 neutral          0 FALSE       ok     
#> 4 SYN_004 pass_01 concise     100 negative         5 TRUE        ok     
#> 5 SYN_005 pass_01 concise     100 positive         0 TRUE        ok     
#> 6 SYN_006 pass_01 concise     100 neutral          4 TRUE        ok     
#> 7 SYN_001 pass_02 concise     200 neutral          9 FALSE       ok     
#> 8 SYN_002 pass_02 concise     200 negative         4 TRUE        ok     
#> # ℹ 1 more variable: .attempts <int>
audit_log_verify(audit_file)
#> <airgap_audit_verification> [VALID]
#>   Entries verified: 1
#>   Chain head hash:  sha256:566977e5385742f8ad91d3e75c28739b39f3440bc35e5b8201559f14640d5d66
```

## 2. Quasi-Identifier $`k`$-Anonymity & $`l`$-Diversity Export Audits

Removing direct identifiers (names, emails, SSNs, MRNs) does **not**
guarantee anonymity if combinations of indirect quasi-identifiers (such
as study `site`, `age_band`, and `wave`) single out small subgroups.

Consider a synthetic extracted clinical table prepared for secondary
analysis:

``` r

export_df <- tibble(
  site = c(rep("Site_North", 6), rep("Site_South", 2), "Site_East", rep("Site_West", 5)),
  age_band = c(rep("30-39", 6), rep("50-59", 2), "70-79", rep("30-39", 5)),
  severity_tier = c(
    "mild", "moderate", "mild", "mild", "severe", "moderate",
    "severe", "severe",
    "severe",
    "mild", "moderate", "severe", "mild", "moderate"
  )
)

# Audit against k >= 5 anonymity and l >= 2 distinct severity outcomes per class
risk_before <- assess_reidentification_risk(
  data = export_df,
  quasi_ids = c("site", "age_band"),
  k_min = 5L,
  sensitive_col = "severity_tier",
  l_min = 2L
)
risk_before
#> <airgap_reid_risk> [k-anonymity (k>=5): FAIL]
#>   Quasi-identifiers:   site, age_band
#>   Rows evaluated:      14 / 14 across 4 equivalence class(es)
#>   Min / Median k:      1 / 3.5
#>   Sample uniques (k=1):1 (7.14%)
#>   Rows with k < 5:     3 (21.43%)
#>   Prosecutor risk:     max=1.0000 | mean=0.2857
#>   Journalist risk:     max=1.0000 | mean=0.2857 (f=1)
#>   l-diversity ('severity_tier', l>=2): FAIL (min_l=1, violating rows=3 [21.43%])
```

Notice that `Site_South` ($`k = 2`$, $`l = 1`$) and `Site_East`
($`k = 1`$, a sample unique with prosecutor risk $`1.00`$) fail both
$`k`$-anonymity and $`l`$-diversity. Compare the two safe mitigation
strategies in
[`apply_k_anonymity()`](https://marcusharrisphd.com/airgapllm/reference/apply_k_anonymity.md):

``` r

# Option A: Suppress violating rows cleanly
suppressed <- apply_k_anonymity(
  data = export_df,
  quasi_ids = c("site", "age_band"),
  k_min = 5L,
  strategy = "suppress_rows",
  sensitive_col = "severity_tier",
  l_min = 2L
)
suppressed
#> <airgap_k_anonymized> [strategy=suppress_rows, k_min=5]
#>   Rows:            14 -> 11 (suppressed=3, masked=0)
#>   k-anonymity:     FAIL -> PASS (min_k: 1 -> 5)
#>   Prosecutor max:  1.0000 -> 0.2000

# Option B: Mask rare classes (progressively absorbing smallest residual class so
# the masked fallback class itself strictly satisfies k >= 5 and l >= 2)
masked <- apply_k_anonymity(
  data = export_df,
  quasi_ids = c("site", "age_band"),
  k_min = 5L,
  strategy = "mask_rare",
  sensitive_col = "severity_tier",
  l_min = 2L
)
masked
#> <airgap_k_anonymized> [strategy=mask_rare, k_min=5]
#>   Rows:            14 -> 14 (suppressed=0, masked=8)
#>   k-anonymity:     FAIL -> PASS (min_k: 1 -> 6)
#>   Prosecutor max:  1.0000 -> 0.1667
```

Both strategies reduce maximum prosecutor risk from `1.0000` to
`<= 0.2000` and achieve `PASS` on both $`k`$-anonymity and
$`l`$-diversity without logging any raw participant values.

## 3. Hardware-Aware Auto-Tuning & Throughput Benchmarking

Before launching a 10,000-row extraction job on a lab workstation or
university HPC GPU node, query
[`recommend_runtime_config()`](https://marcusharrisphd.com/airgapllm/reference/recommend_runtime_config.md)
to select an OOM-safe parameter tier, quantization, context window,
batch size, and container memory limits:

``` r

# Single 24 GB lab workstation GPU (e.g., RTX 4090 / L4)
rec_ws <- recommend_runtime_config(
  vram_gb = 24,
  ram_gb = 64,
  n_gpus = 1L,
  n_docs = 10000L,
  avg_tokens = 1100L,
  priority = "balanced",
  backend = "ollama"
)
rec_ws
#> <airgap_runtime_recommendation> [backend=ollama, priority=balanced]
#>   Hardware:        1x 24 GB GPU (24 GB total) | 64 GB RAM
#>   Recommended:     14B open-weights (Q8_0)
#>   Context / Batch: 4096 tokens | batch_size=4 | KV=FP16
#>   Est. Memory:     18.10 GB (75.4% utilization)
#>   Container Spec:  gpu='nvidia', memory_limit='27g', shm_size='2g'

# Multi-GPU HPC node (2x 80 GB A100/H100) tuned for accuracy on vLLM
rec_hpc <- recommend_runtime_config(
  vram_gb = 80,
  ram_gb = 256,
  n_gpus = 2L,
  n_docs = 25000L,
  avg_tokens = 1500L,
  priority = "accuracy",
  backend = "vllm"
)
rec_hpc
#> <airgap_runtime_recommendation> [backend=vllm, priority=accuracy]
#>   Hardware:        2x 80 GB GPU (160 GB total) | 256 GB RAM
#>   Recommended:     70B open-weights (FP16)
#>   Context / Batch: 4096 tokens | batch_size=4 | KV=FP16
#>   Est. Memory:     137.04 GB (85.7% utilization)
#>   Container Spec:  gpu='nvidia', memory_limit='192g', shm_size='16g', TP=2
```

Finally, run a quick pilot benchmark via
[`benchmark_local_runtime()`](https://marcusharrisphd.com/airgapllm/reference/benchmark_local_runtime.md)
to measure empirical throughput, p50/p95 per-row latency, repair retry
rate, and projected walltime ETA for your full corpus:

``` r

bm <- benchmark_local_runtime(
  runtime = runtime_mock(
    model = "llama3.1:8b-instruct-q4_K_M",
    seed = 42L,
    malform_schedule = list(BM_0002 = c("{invalid_json"))
  ),
  schema = clinical_schema,
  data = synthetic_notes,
  text_col = "note_text",
  n_sample = 8L,
  corpus_size = 10000L
)
bm
#> <airgap_benchmark> [mock | llama3.1:8b-instruct-q4_K_M]
#>   Sample rows:     8 (succeeded=8 [100%], failed=0)
#>   Repair retries:  1 total (12.5% of rows retried)
#>   Throughput:      296.30 rows/sec (elapsed=0.027s)
#>   Latency (ms):    p50=1 | p95=3.3 | mean=1.5 (range 1-4)
#>   Projected ETA:   33.7 sec for 10000 rows
```
