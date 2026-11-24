# Pillar 8 (v0.4.0): Hardware-Aware Auto-Tuner & Local Runtime Benchmarker

#' Format duration in seconds into concise human-readable ETA string
#' @noRd
format_eta_seconds <- function(sec) {
  if (is.na(sec) || !is.finite(sec) || sec < 0) return("NA")
  if (sec < 60) return(sprintf("%.1f sec", sec))
  if (sec < 3600) return(sprintf("%.1f min", sec / 60))
  sprintf("%.2f hr", sec / 3600)
}

#' Recommend Optimal Local LLM Configuration for Workstation or HPC Hardware
#'
#' Computes hardware-aware local model sizing, quantization, context window,
#' concurrency (`batch_size`), KV-cache precision, and hardened container memory
#' limits given available GPU VRAM, host RAM, GPU count, corpus size, and
#' average document length. Evaluates open-weights parameter tiers (`3B`, `8B`,
#' `14B`, `32B`, `70B`) against [estimate_vram_requirements()] so research labs
#' avoid GPU out-of-memory failures on lab workstations and HPC Slurm nodes.
#'
#' @param vram_gb Non-negative numeric VRAM per GPU in gigabytes (e.g., `16`,
#'   `24`, `48`, `80`; pass `0` for CPU-only workstations).
#' @param ram_gb Positive numeric host system RAM in gigabytes (default `32`).
#' @param n_gpus Positive integer number of GPUs allocated (default `1L`).
#' @param n_docs Positive integer expected corpus row count (default `1000L`).
#' @param avg_tokens Positive integer average tokens per input document
#'   (default `800L`).
#' @param priority Optimization goal: `"balanced"` (default), `"accuracy"`
#'   (favors larger parameter count and higher precision), or `"throughput"`
#'   (favors higher concurrent batching and faster quantized weights).
#' @param backend Target local container runtime: `"ollama"` (default),
#'   `"llama.cpp"`, or `"vllm"`.
#' @param safety_margin Numeric VRAM utilization ceiling in `(0.5, 0.98]` to
#'   leave headroom against CUDA fragmentation (default `0.88`).
#'
#' @return An S3 object of class `"airgap_runtime_recommendation"` containing
#'   `hardware`, `workload`, `recommended` (list of optimal settings and
#'   container memory limits), `vram_estimate` (`airgap_vram_estimate`),
#'   `candidates` (ranked feasible tibble), and `rationale` (character vector).
#'
#' @export
#' @examples
#' recommend_runtime_config(vram_gb = 24, ram_gb = 64, n_docs = 5000L, avg_tokens = 1200L)
#' recommend_runtime_config(vram_gb = 80, n_gpus = 2L, priority = "accuracy", backend = "vllm")
recommend_runtime_config <- function(
  vram_gb,
  ram_gb = 32,
  n_gpus = 1L,
  n_docs = 1000L,
  avg_tokens = 800L,
  priority = c("balanced", "accuracy", "throughput"),
  backend = c("ollama", "llama.cpp", "vllm"),
  safety_margin = 0.88
) {
  if (!is.numeric(vram_gb) || length(vram_gb) != 1L || is.na(vram_gb) || !is.finite(vram_gb) || vram_gb < 0) {
    cli::cli_abort("{.arg vram_gb} must be a non-negative finite number.", class = "airgap_validation_error")
  }
  if (!is.numeric(ram_gb) || length(ram_gb) != 1L || is.na(ram_gb) || !is.finite(ram_gb) || ram_gb <= 0) {
    cli::cli_abort("{.arg ram_gb} must be a positive finite number.", class = "airgap_validation_error")
  }
  n_gpus <- assert_scalar_int(n_gpus, "n_gpus", min = 1L)
  n_docs <- assert_scalar_int(n_docs, "n_docs", min = 1L)
  avg_tokens <- assert_scalar_int(avg_tokens, "avg_tokens", min = 64L)
  priority <- match.arg(priority)
  backend <- match.arg(backend)
  if (!is.numeric(safety_margin) || length(safety_margin) != 1L || is.na(safety_margin) ||
      !is.finite(safety_margin) || safety_margin <= 0.5 || safety_margin > 0.98) {
    cli::cli_abort("{.arg safety_margin} must be a finite number in (0.5, 0.98].", class = "airgap_validation_error")
  }

  # Choose power-of-2 context window accommodating input + schema prompt + structured output
  needed_ctx <- ceiling((avg_tokens + 768) * 1.35)
  ctx_tiers <- c(2048L, 4096L, 8192L, 16384L, 32768L)
  ctx_idx <- which(ctx_tiers >= needed_ctx)
  context_length <- if (length(ctx_idx) > 0L) ctx_tiers[ctx_idx[1L]] else 32768L
  chunking_rec <- needed_ctx > 16384

  cpu_only <- vram_gb == 0
  total_vram <- if (cpu_only) 0 else (vram_gb * n_gpus)
  usable_budget <- if (cpu_only) (ram_gb * 0.55) else (total_vram * safety_margin)

  # Candidate grid across realistic open-weights clinical research tiers
  param_grid <- c(3, 8, 14, 32, 70)
  quant_grid <- c("Q4_K_M", "Q6_K", "Q8_0", "FP16")
  batch_grid <- if (cpu_only) 1L else if (identical(backend, "vllm")) c(1L, 2L, 4L, 8L, 16L) else c(1L, 2L, 4L)
  kv_q <- if (usable_budget <= 12) "Q8_0" else "FP16"

  quant_quality <- c("Q4_K_M" = 0.86, "Q6_K" = 0.94, "Q8_0" = 0.98, "FP16" = 1.00)
  quant_speed <- c("Q4_K_M" = 1.35, "Q6_K" = 1.15, "Q8_0" = 1.00, "FP16" = 0.72)

  rows <- list()
  for (pb in param_grid) {
    for (q in quant_grid) {
      # vLLM prefers FP16/Q8_0/Q4_K_M; still allow scoring all candidates transparently
      for (bs in batch_grid) {
        est <- estimate_vram_requirements(
          params_b = pb,
          quantization = q,
          context_length = context_length,
          batch_size = bs,
          kv_cache_quant = kv_q,
          overhead_gb = if (cpu_only) 0.8 else 1.2
        )
        if (est$total_vram_gb <= usable_budget) {
          cap_score <- log2(pb + 1) * quant_quality[[q]]
          # Approximate relative throughput proxy (inversely proportional to active weight size, scales sublinearly with batch)
          speed_score <- (quant_speed[[q]] / (pb^0.75)) * (bs^0.65)
          total_score <- switch(
            priority,
            "accuracy" = 3.0 * cap_score + 0.15 * log2(bs + 1),
            "throughput" = 0.8 * cap_score + 3.5 * log2(1 + speed_score * 20),
            "balanced" = 2.0 * cap_score + 1.0 * log2(1 + speed_score * 15)
          )
          rows[[length(rows) + 1L]] <- list(
            params_b = pb,
            quantization = q,
            batch_size = as.integer(bs),
            context_length = as.integer(context_length),
            kv_cache_quant = kv_q,
            estimated_vram_gb = est$total_vram_gb,
            utilization_pct = round(100 * est$total_vram_gb / max(1, if (cpu_only) ram_gb else total_vram), 1),
            score = round(total_score, 4)
          )
        }
      }
    }
  }

  fallback_used <- length(rows) == 0L
  feasible <- !fallback_used

  if (fallback_used) {
    # Ultra-constrained fallback: 3B Q4_K_M at 2048 context
    context_length <- 2048L
    est_fb <- estimate_vram_requirements(3, "Q4_K_M", context_length = context_length, batch_size = 1L, kv_cache_quant = "Q4_0", overhead_gb = 0.6)
    feasible <- isTRUE(est_fb$total_vram_gb <= usable_budget)
    rows[[1L]] <- list(
      params_b = 3,
      quantization = "Q4_K_M",
      batch_size = 1L,
      context_length = context_length,
      kv_cache_quant = "Q4_0",
      estimated_vram_gb = est_fb$total_vram_gb,
      utilization_pct = round(100 * est_fb$total_vram_gb / max(1, if (cpu_only) ram_gb else total_vram), 1),
      score = 0
    )
    chunking_rec <- TRUE
    if (!feasible) {
      cli::cli_warn(
        c(
          "No candidate local model configuration fits within the available usable memory budget ({round(usable_budget, 2)} GB).",
          "!" = "Fallback 3B Q4_K_M requires ~{est_fb$total_vram_gb} GB ({rows[[1L]]$utilization_pct}% utilization) and risks OOM.",
          "i" = "Allocate additional GPU VRAM / host RAM or switch to CPU-only mode with sufficient system RAM."
        ),
        class = "airgap_hardware_warning"
      )
    }
  }

  cand_tbl <- tibble::tibble(
    params_b = vapply(rows, `[[`, numeric(1L), "params_b"),
    quantization = vapply(rows, `[[`, character(1L), "quantization"),
    batch_size = vapply(rows, `[[`, integer(1L), "batch_size"),
    context_length = vapply(rows, `[[`, integer(1L), "context_length"),
    kv_cache_quant = vapply(rows, `[[`, character(1L), "kv_cache_quant"),
    estimated_vram_gb = vapply(rows, `[[`, numeric(1L), "estimated_vram_gb"),
    utilization_pct = vapply(rows, `[[`, numeric(1L), "utilization_pct"),
    score = vapply(rows, `[[`, numeric(1L), "score")
  )
  cand_tbl <- cand_tbl[order(-cand_tbl$score, -cand_tbl$params_b, -cand_tbl$batch_size), , drop = FALSE]
  best <- cand_tbl[1L, , drop = FALSE]

  best_vram_est <- estimate_vram_requirements(
    params_b = best$params_b,
    quantization = best$quantization,
    context_length = best$context_length,
    batch_size = best$batch_size,
    kv_cache_quant = best$kv_cache_quant,
    overhead_gb = if (fallback_used) 0.6 else if (cpu_only) 0.8 else 1.2
  )

  # Container host memory & shared memory sizing — strictly capped at physical host ram_gb
  if (ram_gb >= 1) {
    ram_cap_gb <- as.integer(floor(ram_gb))
    target_mem_gb <- max(4L, as.integer(floor(min(ram_gb * 0.75, max(8, best$estimated_vram_gb * 1.5)))))
    container_mem_gb <- max(1L, min(ram_cap_gb, target_mem_gb))
    raw_shm_gb <- if (identical(backend, "vllm")) max(2L, min(16L, as.integer(ceiling(container_mem_gb * 0.25)))) else 2L
    shm_gb <- min(max(1L, as.integer(floor(container_mem_gb / 2))), raw_shm_gb)
    container_mem_str <- paste0(container_mem_gb, "g")
    container_shm_str <- paste0(shm_gb, "g")
  } else {
    ram_cap_mb <- max(128L, as.integer(floor(ram_gb * 1024)))
    shm_mb <- max(64L, as.integer(floor(ram_cap_mb / 4)))
    container_mem_str <- paste0(ram_cap_mb, "m")
    container_shm_str <- paste0(shm_mb, "m")
  }

  tier_label <- paste0(best$params_b, "B open-weights (", best$quantization, ")")
  rationale <- c(
    paste0(
      if (cpu_only) paste0("CPU-only mode budgeted at ", round(usable_budget, 1), " GB of ", ram_gb, " GB host RAM.")
      else paste0("GPU budget: ", round(usable_budget, 1), " GB usable (", round(safety_margin * 100), "% of ", total_vram, " GB across ", n_gpus, " GPU(s)).")
    ),
    paste0(
      "Selected ", tier_label, " with context=", best$context_length,
      " and batch_size=", best$batch_size, " for priority='", priority, "' (",
      best$estimated_vram_gb, " GB estimated)."
    ),
    paste0(
      "Container memory limit set to ", container_mem_str, " (shm_size=", container_shm_str,
      ") for backend='", backend, "'."
    )
  )
  if (!feasible) {
    rationale <- c(
      rationale,
      "WARNING: Hardware budget is below minimum 3B Q4_K_M VRAM requirements; configuration is marked infeasible (OOM risk)."
    )
  }
  if (isTRUE(chunking_rec)) {
    rationale <- c(
      rationale,
      "Long average document length detected: use `chunk_clinical_texts()` before `airgap_extract()`."
    )
  }

  structure(
    list(
      hardware = list(
        vram_gb = as.numeric(vram_gb),
        n_gpus = n_gpus,
        total_vram_gb = as.numeric(total_vram),
        ram_gb = as.numeric(ram_gb),
        gpu_mode = if (cpu_only) "none" else "nvidia"
      ),
      workload = list(
        n_docs = n_docs,
        avg_tokens = avg_tokens,
        priority = priority,
        backend = backend
      ),
      recommended = list(
        feasible = isTRUE(feasible),
        params_b = best$params_b,
        model_tier = tier_label,
        quantization = best$quantization,
        context_length = best$context_length,
        batch_size = best$batch_size,
        kv_cache_quant = best$kv_cache_quant,
        estimated_vram_gb = best$estimated_vram_gb,
        vram_utilization_pct = best$utilization_pct,
        container_memory_limit = container_mem_str,
        container_shm_size = container_shm_str,
        gpu_flag = if (cpu_only) "none" else "nvidia",
        tensor_parallel_size = if (!cpu_only && n_gpus > 1L) n_gpus else 1L,
        chunking_recommended = isTRUE(chunking_rec)
      ),
      vram_estimate = best_vram_est,
      candidates = utils::head(cand_tbl, 10L),
      rationale = rationale
    ),
    class = "airgap_runtime_recommendation"
  )
}

#' @export
print.airgap_runtime_recommendation <- function(x, ...) {
  r <- x$recommended
  cat("<airgap_runtime_recommendation> [backend=", x$workload$backend,
      ", priority=", x$workload$priority,
      if (isFALSE(r$feasible)) ", INFEASIBLE/OOM RISK" else "",
      "]\n", sep = "")
  cat("  Hardware:        ",
      if (x$hardware$gpu_mode == "none") paste0("CPU-only (", x$hardware$ram_gb, " GB RAM)")
      else paste0(x$hardware$n_gpus, "x ", x$hardware$vram_gb, " GB GPU (", x$hardware$total_vram_gb, " GB total) | ", x$hardware$ram_gb, " GB RAM"),
      "\n", sep = "")
  cat("  Recommended:     ", r$model_tier, "\n", sep = "")
  cat("  Context / Batch: ", r$context_length, " tokens | batch_size=", r$batch_size,
      " | KV=", r$kv_cache_quant, "\n", sep = "")
  cat("  Est. Memory:     ", sprintf("%.2f GB (%.1f%% utilization)", r$estimated_vram_gb, r$vram_utilization_pct), "\n", sep = "")
  cat("  Container Spec:  gpu='", r$gpu_flag, "', memory_limit='", r$container_memory_limit,
      "', shm_size='", r$container_shm_size, "'",
      if (r$tensor_parallel_size > 1L) paste0(", TP=", r$tensor_parallel_size) else "",
      "\n", sep = "")
  invisible(x)
}

#' Benchmark Throughput, Latency Quantiles, and Retry Rate on a Local Runtime
#'
#' Runs a controlled offline pilot benchmark of [airgap_extract()] on a sample
#' of rows (supplied via `data` or generated synthetically when `data = NULL`)
#' using any local or mock runtime, reporting throughput (`rows_per_sec`),
#' estimated full-corpus ETA, schema validation success rate, repair retry
#' rate, and per-row latency quantiles (`min`, `p50`, `mean`, `p95`, `max` in
#' milliseconds). Never stores or prints raw participant text.
#'
#' @param runtime An `airgap_runtime` object from [runtime_ollama()],
#'   [runtime_openai_local()], or [runtime_mock()].
#' @param schema An [extraction_schema()] object.
#' @param data Optional data frame containing sample text rows. If `NULL`,
#'   synthesizes deterministic synthetic clinical benchmark sentences.
#' @param text_col Character scalar text column name (required when `data` is
#'   supplied).
#' @param n_sample Positive integer number of rows to benchmark (default
#'   `10L`). When `data` has fewer than `n_sample` rows, benchmarks all rows of
#'   `data`.
#' @param corpus_size Optional positive integer target full-corpus size used to
#'   project estimated runtime ETA. Defaults to `nrow(data)` when `data` is
#'   supplied, or `1000L` otherwise.
#' @param pii_policy Pre-inference privacy policy: `"redact"` (default) or
#'   `"verified_deidentified"`.
#' @param pii_config Optional [pii_config()] object.
#' @param max_retries Non-negative integer maximum structured repair retries
#'   per row (default `2L`).
#' @param prompt_template Optional prompt template override.
#' @param container_spec Optional [airgap_container_spec()].
#'
#' @return An S3 object of class `"airgap_benchmark"` containing `model`,
#'   `backend_type`, `n_sample`, `rows_succeeded`, `rows_failed`,
#'   `success_rate_pct`, `total_retries`, `repair_retry_rate_pct`,
#'   `elapsed_sec`, `rows_per_sec`, `latency_ms` (list of `min`, `p50`, `mean`,
#'   `p95`, `max`), `corpus_size`, `estimated_eta_sec`,
#'   `estimated_eta_formatted`, and `benchmarked_at`.
#'
#' @export
#' @examples
#' sc <- extraction_schema(
#'   sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
#'   severity = schema_field("integer", min = 0L, max = 10L)
#' )
#' bm <- benchmark_local_runtime(runtime_mock(seed = 42L), sc, n_sample = 6L, corpus_size = 5000L)
#' bm
benchmark_local_runtime <- function(
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
) {
  if (!inherits(runtime, "airgap_runtime")) {
    cli::cli_abort("{.arg runtime} must be an `airgap_runtime` object.", class = "airgap_validation_error")
  }
  if (!inherits(schema, "airgap_schema")) {
    cli::cli_abort("{.arg schema} must be an `airgap_schema` object.", class = "airgap_validation_error")
  }
  pii_policy <- match.arg(pii_policy)
  n_sample <- assert_scalar_int(n_sample, "n_sample", min = 1L)
  corpus_size <- assert_scalar_int(corpus_size, "corpus_size", min = 1L, allow_null = TRUE)
  max_retries <- assert_scalar_int(max_retries, "max_retries", min = 0L)

  if (is.null(data)) {
    base_texts <- c(
      "Patient: Jordan Ellis (MRN: 000101) reported steady sleep improvement on 2026-01-14.",
      "Follow-up with Dr. Hannah Park via jordan.ellis@example.org; anxiety mild, no crisis.",
      "Progress note: Cognitive Behavioral Therapy homework completed; affect calm and engaged.",
      "Evening EMA entry: moderate energy, strong social support, zero acute distress."
    )
    sample_df <- tibble::tibble(
      .bench_id = sprintf("BM_%04d", seq_len(n_sample)),
      .bench_text = base_texts[((seq_len(n_sample) - 1L) %% length(base_texts)) + 1L]
    )
    eff_text_col <- ".bench_text"
    eff_id_col <- ".bench_id"
    eff_corpus <- if (is.null(corpus_size)) 1000L else corpus_size
  } else {
    if (!is.data.frame(data) || nrow(data) == 0L) {
      cli::cli_abort("{.arg data} must be a non-empty data frame.", class = "airgap_validation_error")
    }
    if (is.null(text_col)) {
      cli::cli_abort("Specify {.arg text_col} when supplying {.arg data} to `benchmark_local_runtime()`.", class = "airgap_validation_error")
    }
    assert_scalar_string(text_col, "text_col")
    if (!text_col %in% names(data)) {
      cli::cli_abort("Column {.val {text_col}} not found in {.arg data}.", class = "airgap_validation_error")
    }
    take_n <- min(n_sample, nrow(data))
    sample_df <- tibble::tibble(
      .bench_id = sprintf("BM_%04d", seq_len(take_n)),
      .bench_text = as.character(data[[text_col]][seq_len(take_n)])
    )
    eff_text_col <- ".bench_text"
    eff_id_col <- ".bench_id"
    eff_corpus <- if (is.null(corpus_size)) as.integer(nrow(data)) else corpus_size
  }

  t0 <- proc.time()[["elapsed"]]
  res <- airgap_extract(
    data = sample_df,
    text_col = eff_text_col,
    schema = schema,
    runtime = runtime,
    prompt_template = prompt_template,
    id_col = eff_id_col,
    pii_policy = pii_policy,
    pii_config = pii_config,
    max_retries = max_retries,
    container_spec = container_spec,
    progress = FALSE
  )
  elapsed_sec <- max(proc.time()[["elapsed"]] - t0, 1e-6)

  tp <- extraction_throughput(res)
  n_eval <- nrow(res)
  lat <- as.numeric(res$.elapsed_ms)
  lat <- lat[is.finite(lat)]
  if (length(lat) == 0L) lat <- 0

  q_vals <- as.numeric(stats::quantile(lat, probs = c(0.50, 0.95), names = FALSE, type = 7))
  rows_per_sec <- n_eval / elapsed_sec
  eta_sec <- eff_corpus / max(rows_per_sec, 1e-6)
  n_retried_rows <- sum(res$.attempts > 1L, na.rm = TRUE)

  structure(
    list(
      model = runtime$model,
      backend_type = runtime$backend_type,
      n_sample = as.integer(n_eval),
      rows_succeeded = as.integer(tp$rows_succeeded),
      rows_failed = as.integer(tp$rows_failed),
      success_rate_pct = round(100 * tp$rows_succeeded / n_eval, 2),
      total_retries = as.integer(tp$total_retries),
      repair_retry_rate_pct = round(100 * n_retried_rows / n_eval, 2),
      elapsed_sec = round(elapsed_sec, 4),
      rows_per_sec = round(rows_per_sec, 2),
      latency_ms = list(
        min = round(min(lat), 2),
        p50 = round(q_vals[1L], 2),
        mean = round(mean(lat), 2),
        p95 = round(q_vals[2L], 2),
        max = round(max(lat), 2)
      ),
      corpus_size = as.integer(eff_corpus),
      estimated_eta_sec = round(eta_sec, 2),
      estimated_eta_formatted = format_eta_seconds(eta_sec),
      benchmarked_at = utc_timestamp()
    ),
    class = "airgap_benchmark"
  )
}

#' @export
print.airgap_benchmark <- function(x, ...) {
  cat("<airgap_benchmark> [", x$backend_type, " | ", x$model, "]\n", sep = "")
  cat("  Sample rows:     ", x$n_sample, " (succeeded=", x$rows_succeeded,
      " [", x$success_rate_pct, "%], failed=", x$rows_failed, ")\n", sep = "")
  cat("  Repair retries:  ", x$total_retries, " total (", x$repair_retry_rate_pct, "% of rows retried)\n", sep = "")
  cat("  Throughput:      ", sprintf("%.2f rows/sec", x$rows_per_sec),
      " (elapsed=", sprintf("%.3fs", x$elapsed_sec), ")\n", sep = "")
  cat("  Latency (ms):    p50=", x$latency_ms$p50, " | p95=", x$latency_ms$p95,
      " | mean=", x$latency_ms$mean, " (range ", x$latency_ms$min, "-", x$latency_ms$max, ")\n", sep = "")
  cat("  Projected ETA:   ", x$estimated_eta_formatted, " for ", x$corpus_size, " rows\n", sep = "")
  invisible(x)
}
