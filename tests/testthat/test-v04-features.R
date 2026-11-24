# v0.4.0 Tests: k-Anonymity / l-Diversity, Multi-Pass Consensus, Auto-Tuner & Benchmarker

test_that("assess_reidentification_risk computes exact k-anonymity, risk metrics, and l-diversity", {
  df <- tibble::tibble(
    site = c(rep("North", 5), rep("South", 2), "East", rep("West", 5)),
    age_band = c(rep("30-39", 5), rep("40-49", 2), "60-69", rep("30-39", 5)),
    diagnosis = c(
      "anxiety", "anxiety", "anxiety", "anxiety", "anxiety", # k=5, l=1 (violates l=2!)
      "depression", "bipolar",                                # k=2 (violates k=5), l=2
      "ptsd",                                                 # k=1 (unique!), l=1
      "anxiety", "depression", "anxiety", "bipolar", "ptsd"   # k=5, l=4 (passes both)
    )
  )

  r <- assess_reidentification_risk(
    df,
    quasi_ids = c("site", "age_band"),
    k_min = 5L,
    sensitive_col = "diagnosis",
    l_min = 2L,
    sampling_fraction = 0.5
  )
  expect_s3_class(r, "airgap_reid_risk")
  expect_equal(r$n_rows, 13L)
  expect_equal(r$n_classes, 4L)
  expect_equal(r$min_k, 1L)
  expect_equal(r$n_unique_rows, 1L)
  expect_equal(r$n_violating_classes, 2L)
  expect_equal(r$n_violating_rows, 3L)
  expect_false(r$passes_k_anonymity)
  expect_equal(r$prosecutor_risk_max, 1.0)
  expect_equal(r$prosecutor_risk_mean, round(4 / 13, 4))
  expect_equal(r$journalist_risk_max, 0.5)
  expect_false(r$passes_l_diversity)
  expect_equal(r$min_l, 1L)
  expect_equal(r$n_l_violating_rows, 6L) # North (5) + East (1)
  expect_output(print(r), "airgap_reid_risk")

  # Verify printed output and equivalence_classes NEVER contain raw quasi-ID or diagnosis values
  out_txt <- paste(capture.output(print(r)), collapse = "\n")
  for (raw_val in c("North", "South", "East", "60-69", "bipolar", "ptsd")) {
    expect_false(grepl(raw_val, out_txt, fixed = TRUE))
  }

  # NA handling: include_na = FALSE excludes rows with NA quasi-IDs cleanly
  df_na <- df
  df_na$site[1L] <- NA_character_
  r_excl <- assess_reidentification_risk(df_na, c("site", "age_band"), k_min = 4L, include_na = FALSE)
  expect_equal(r_excl$n_rows_excluded_na, 1L)
  expect_equal(r_excl$n_rows_evaluated, 12L)

  # 0-row data frame handled gracefully
  empty_df <- tibble::tibble(site = character(), age_band = character())
  r_empty <- assess_reidentification_risk(empty_df, c("site", "age_band"), k_min = 5L)
  expect_true(r_empty$passes_k_anonymity)
  expect_equal(r_empty$n_rows_evaluated, 0L)

  # Validation errors
  expect_error(assess_reidentification_risk("not_df", "site"), class = "airgap_validation_error")
  expect_error(assess_reidentification_risk(df, character()), class = "airgap_validation_error")
  expect_error(assess_reidentification_risk(df, "missing_col"), class = "airgap_validation_error")
  expect_error(assess_reidentification_risk(df, "site", k_min = 1L), class = "airgap_validation_error")
  expect_error(assess_reidentification_risk(df, "site", sensitive_col = "site"), class = "airgap_validation_error")
  expect_error(assess_reidentification_risk(df, "site", sensitive_col = "missing"), class = "airgap_validation_error")
  expect_error(assess_reidentification_risk(df, "site", sensitive_col = "diagnosis", l_min = 1L), class = "airgap_validation_error")
  expect_error(assess_reidentification_risk(df, "site", sampling_fraction = 1.5), class = "airgap_validation_error")
})

test_that("apply_k_anonymity enforces k-anonymity & l-diversity under suppress_rows and mask_rare", {
  df <- tibble::tibble(
    site = c(rep("North", 6), rep("South", 2), "East", rep("West", 5)),
    wave = c(rep(1L, 6), rep(2L, 2), 2L, rep(1L, 5)),
    outcome = c("A", "B", "A", "B", "C", "A", "A", "B", "C", "A", "B", "C", "A", "B")
  )

  # Strategy 1: suppress_rows removes the 3 violating rows (South=2, East=1)
  res_sup <- apply_k_anonymity(df, c("site", "wave"), k_min = 5L, strategy = "suppress_rows",
                               sensitive_col = "outcome", l_min = 2L)
  expect_s3_class(res_sup, "airgap_k_anonymized")
  expect_equal(res_sup$n_rows_before, 14L)
  expect_equal(res_sup$n_rows_after, 11L)
  expect_equal(res_sup$n_rows_suppressed, 3L)
  expect_true(res_sup$risk_after$passes_k_anonymity)
  expect_true(res_sup$risk_after$passes_l_diversity)
  expect_lt(res_sup$risk_after$prosecutor_risk_max, res_sup$risk_before$prosecutor_risk_max)
  expect_output(print(res_sup), "airgap_k_anonymized")

  # Strategy 2: mask_rare absorbs smallest remaining class (West=5) so masked class has 8 >= 5 rows
  res_mask <- apply_k_anonymity(df, c("site", "wave"), k_min = 5L, strategy = "mask_rare",
                                sensitive_col = "outcome", l_min = 2L)
  expect_equal(res_mask$n_rows_after, 14L)
  expect_equal(res_mask$n_rows_suppressed, 0L)
  expect_equal(res_mask$n_rows_masked, 8L)
  expect_true(res_mask$risk_after$passes_k_anonymity)
  expect_true(res_mask$risk_after$passes_l_diversity)
  expect_true("[SUPPRESSED]" %in% res_mask$data$site)

  # Tiny dataset (< k_min rows total) under mask_rare masks all rows cleanly and warns of non-compliance
  tiny <- df[1:3, ]
  expect_warning(
    res_tiny <- apply_k_anonymity(tiny, c("site", "wave"), k_min = 5L, strategy = "mask_rare", mask_value = NA_character_),
    class = "airgap_anonymity_warning"
  )
  expect_equal(res_tiny$n_rows_masked, 3L)
  expect_true(all(is.na(res_tiny$data$site)))
})

test_that("airgap_extract_consensus aggregates multi-seed and crossed prompt passes accurately", {
  df <- tibble::tibble(
    id = c("U1", "U2", "U3"),
    note = c(
      "Patient: Jane Doe (jane@example.org) felt calm and rested.",
      "Mild anxiety before exam; sleep 6 hours.",
      "Moderate tension reported at follow-up."
    )
  )
  sc <- extraction_schema(
    mood = schema_field("enum", values = c("calm", "anxious", "tense")),
    score = schema_field("integer", min = 0L, max = 10L),
    conf = schema_field("numeric", min = 0, max = 1, nullable = TRUE),
    flag = schema_field("logical"),
    note_tag = schema_field("character")
  )

  # Deterministic custom handler returning controlled pass-varying votes to verify exact math
  call_counter <- new.env(parent = emptyenv())
  call_counter$n <- 0L
  rt_custom <- runtime_mock(
    handler = function(prompt, row_id, attempt, schema) {
      # Encode pass variation via prompt prefix or call count
      call_counter$n <- call_counter$n + 1L
      pass_num <- ((call_counter$n - 1L) %/% 3L) + 1L
      if (row_id == "U1") {
        # Unanimous across all 3 passes
        list(mood = "calm", score = 2L, conf = 0.9, flag = FALSE, note_tag = "ok")
      } else if (row_id == "U2") {
        # 2-vs-1 majority on mood/flag; numeric scores 4, 6, 8 -> median = 6
        moods <- c("anxious", "anxious", "tense")
        scores <- c(4L, 6L, 8L)
        flags <- c(TRUE, TRUE, FALSE)
        list(mood = moods[pass_num], score = scores[pass_num], conf = NA, flag = flags[pass_num], note_tag = "watch")
      } else {
        # Exact 3-way tie on mood across 3 passes
        moods <- c("calm", "anxious", "tense")
        list(mood = moods[pass_num], score = 5L, conf = 0.5, flag = TRUE, note_tag = "mixed")
      }
    }
  )

  aud_log <- withr::local_tempfile(fileext = ".audit.jsonl")
  res_first <- airgap_extract_consensus(
    df, "note", sc, rt_custom,
    n_passes = 3L,
    id_col = "id",
    numeric_agg = "median",
    tie_policy = "first",
    audit_log_path = aud_log
  )

  expect_s3_class(res_first, "airgap_consensus")
  expect_s3_class(res_first, "tbl_df")
  expect_equal(res_first$mood, c("calm", "anxious", "calm"))
  expect_identical(res_first$score, c(2L, 6L, 5L))
  expect_true(is.na(res_first$conf[2L]))
  expect_equal(res_first$flag, c(FALSE, TRUE, TRUE))
  expect_equal(res_first$.agreement[1L], 1.0)
  expect_lt(res_first$.agreement[3L], 1.0)
  expect_equal(res_first$.passes_ok, c(3L, 3L, 3L))
  expect_true(audit_log_verify(aud_log)$valid)

  # Long-format pass table directly compatible with G-study designs
  lp <- consensus_passes(res_first)
  expect_equal(nrow(lp), 9L)
  expect_true(all(c("unit_id", "pass_id", "prompt_id", "seed", "mood", "score") %in% names(lp)))

  diag_tbl <- consensus_diagnostics(res_first)
  expect_equal(nrow(diag_tbl), 5L)
  expect_equal(diag_tbl$n_ties[diag_tbl$field == "mood"], 1L)

  # Seamless interop with extraction_manifest() and generate_irb_narrative()
  expect_s3_class(extraction_manifest(res_first), "airgap_run_manifest")
  expect_s3_class(generate_irb_narrative(res_first, protocol_id = "IRB-CONS-01"), "airgap_irb_narrative")

  # tie_policy = "na" returns NA on exact tie + trimmed_mean / mean numeric agg + crossed prompts x seeds
  call_counter$n <- 0L
  res_na <- airgap_extract_consensus(
    df, "note", sc, rt_custom,
    seeds = c(1L, 2L, 3L),
    id_col = "id",
    numeric_agg = "trimmed_mean",
    tie_policy = "na"
  )
  expect_true(is.na(res_na$mood[3L]))

  # Crossed 2 prompts x 2 seeds = 4 passes + pseudonymize + reidentify_output
  key <- pii_vault_key()
  res_crossed <- airgap_extract_consensus(
    df[1:2, ], "note", sc, runtime_mock(seed = 10L),
    seeds = c(10L, 20L),
    prompt_templates = c(brief = "Code text:\n{text}", detailed = "Carefully analyze:\n{text}"),
    id_col = "id",
    pii_policy = "pseudonymize",
    pii_key = key,
    reidentify_output = TRUE,
    numeric_agg = "mean"
  )
  expect_equal(nrow(consensus_passes(res_crossed)), 8L)
  expect_equal(sort(unique(consensus_passes(res_crossed)$prompt_id)), c("brief", "detailed"))
  expect_s3_class(extraction_vault(res_crossed), "airgap_pii_vault")

  # Single pass (< 2) rejected
  expect_error(
    airgap_extract_consensus(df, "note", sc, runtime_mock(), n_passes = 1L),
    class = "airgap_validation_error"
  )
  expect_error(consensus_passes(df), class = "airgap_validation_error")
  expect_error(consensus_diagnostics(df), class = "airgap_validation_error")
})

test_that("recommend_runtime_config and benchmark_local_runtime size and profile local hardware cleanly", {
  # 24 GB workstation vs 2x 80 GB HPC vs CPU-only vs ultra-constrained
  r_24 <- recommend_runtime_config(vram_gb = 24, ram_gb = 64, n_docs = 5000L, avg_tokens = 1000L, priority = "balanced")
  expect_s3_class(r_24, "airgap_runtime_recommendation")
  expect_lte(r_24$recommended$estimated_vram_gb, 24 * 0.88)
  expect_equal(r_24$recommended$gpu_flag, "nvidia")
  expect_output(print(r_24), "airgap_runtime_recommendation")

  r_hpc <- recommend_runtime_config(vram_gb = 80, ram_gb = 256, n_gpus = 2L, priority = "accuracy", backend = "vllm")
  expect_equal(r_hpc$recommended$tensor_parallel_size, 2L)
  expect_gte(r_hpc$recommended$params_b, 32)

  r_tp <- recommend_runtime_config(vram_gb = 48, ram_gb = 128, priority = "throughput", backend = "vllm")
  expect_gte(r_tp$recommended$batch_size, 2L)

  r_cpu <- recommend_runtime_config(vram_gb = 0, ram_gb = 16, avg_tokens = 500L)
  expect_equal(r_cpu$recommended$gpu_flag, "none")
  expect_equal(r_cpu$hardware$gpu_mode, "none")

  # Ultra-constrained fallback & long-document chunking flag (warns of infeasible OOM risk)
  expect_warning(
    r_tiny <- recommend_runtime_config(vram_gb = 2, ram_gb = 8, avg_tokens = 20000L),
    class = "airgap_hardware_warning"
  )
  expect_false(r_tiny$recommended$feasible)
  expect_true(r_tiny$recommended$chunking_recommended)
  expect_equal(r_tiny$recommended$params_b, 3)

  # Validation errors
  expect_error(recommend_runtime_config(vram_gb = -1), class = "airgap_validation_error")
  expect_error(recommend_runtime_config(vram_gb = 24, safety_margin = 0.2), class = "airgap_validation_error")

  # Benchmark on default synthetic rows AND supplied data with scheduled repair retry
  sc <- extraction_schema(
    sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
    severity = schema_field("integer", min = 0L, max = 10L)
  )
  bm_syn <- benchmark_local_runtime(runtime_mock(seed = 1L), sc, n_sample = 5L, corpus_size = 2000L)
  expect_s3_class(bm_syn, "airgap_benchmark")
  expect_equal(bm_syn$n_sample, 5L)
  expect_equal(bm_syn$success_rate_pct, 100)
  expect_equal(bm_syn$repair_retry_rate_pct, 0)
  expect_gt(bm_syn$rows_per_sec, 0)
  expect_output(print(bm_syn), "airgap_benchmark")

  data("synthetic_notes", package = "airgapllm")
  rt_retry <- runtime_mock(
    seed = 2L,
    malform_schedule = list(BM_0001 = c("{bad_json"))
  )
  bm_dat <- benchmark_local_runtime(
    rt_retry, sc,
    data = synthetic_notes[1:4, ],
    text_col = "note_text",
    n_sample = 4L,
    corpus_size = 10000L
  )
  expect_equal(bm_dat$total_retries, 1L)
  expect_equal(bm_dat$repair_retry_rate_pct, 25)
  expect_equal(bm_dat$corpus_size, 10000L)

  expect_error(benchmark_local_runtime("bad", sc), class = "airgap_validation_error")
  expect_error(benchmark_local_runtime(runtime_mock(), sc, data = synthetic_notes), class = "airgap_validation_error")
})
