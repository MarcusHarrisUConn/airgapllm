# v0.3.0 Workflow Depth, Edge-Case Resilience & Dataset Tests

test_that("chunk_clinical_texts splits long transcripts deterministically with overlap and provenance", {
  p1 <- paste(rep("Patient reported steady sleep improvements after stimulus control.", 4), collapse = " ")
  p2 <- paste(rep("Clinician reviewed mindfulness homework and coping anchors.", 4), collapse = " ")
  p3 <- paste(rep("Follow-up appointment confirmed for next month with no crisis flags.", 4), collapse = " ")

  df <- tibble::tibble(
    doc_id = c("T1", "T2", "T3"),
    txt = c(paste(p1, p2, p3, sep = "\n\n"), NA_character_, "")
  )

  ch_para <- chunk_clinical_texts(df, "txt", id_col = "doc_id", max_chars = 320L, overlap_chars = 60L, split_on = "paragraph")
  expect_s3_class(ch_para, "tbl_df")
  expect_true(all(c("doc_id", "chunk_id", "chunk_index", "n_chunks", "start_char", "end_char", "char_count", "chunk_text") %in% names(ch_para)))

  t1_rows <- ch_para[ch_para$doc_id == "T1", ]
  expect_gt(nrow(t1_rows), 1L)
  expect_equal(t1_rows$chunk_index, seq_len(nrow(t1_rows)))
  expect_true(all(t1_rows$n_chunks == nrow(t1_rows)))
  expect_true(all(t1_rows$char_count <= 320L))
  # Consecutive chunks overlap cleanly
  expect_lt(t1_rows$start_char[2L], t1_rows$end_char[1L])
  # Full transcript end reached
  expect_equal(max(t1_rows$end_char), nchar(df$txt[1L], type = "chars"))

  # NA and empty string preserved cleanly as 1-chunk placeholders
  expect_true(is.na(ch_para$chunk_text[ch_para$doc_id == "T2"]))
  expect_equal(ch_para$chunk_text[ch_para$doc_id == "T3"], "")

  # Sentence and character modes also work deterministically
  ch_sent <- chunk_clinical_texts(df[1L, ], "txt", id_col = "doc_id", max_chars = 250L, overlap_chars = 40L, split_on = "sentence")
  ch_char <- chunk_clinical_texts(df[1L, ], "txt", id_col = "doc_id", max_chars = 250L, overlap_chars = 40L, split_on = "character")
  expect_gt(nrow(ch_sent), 1L)
  expect_gt(nrow(ch_char), 1L)

  # 0-row data frame handled gracefully
  empty_df <- tibble::tibble(doc_id = character(), txt = character())
  ch_empty <- chunk_clinical_texts(empty_df, "txt", id_col = "doc_id")
  expect_equal(nrow(ch_empty), 0L)

  # Invalid overlap >= max_chars rejected
  expect_error(
    chunk_clinical_texts(df, "txt", max_chars = 100L, overlap_chars = 100L),
    class = "airgap_validation_error"
  )
})

test_that("pii_audit_dataframe summarizes density, advisories, and strictly masked previews", {
  data("synthetic_notes", package = "airgapllm")
  expect_s3_class(synthetic_notes, "tbl_df")
  expect_equal(nrow(synthetic_notes), 16L)

  aud <- pii_audit_dataframe(
    synthetic_notes,
    "note_text",
    id_col = "note_id",
    high_density_threshold = 3L,
    preview_n = 5L
  )
  expect_s3_class(aud, "airgap_pii_audit")
  expect_s3_class(aud$report, "airgap_privacy_report")
  expect_equal(nrow(aud$row_summary), 16L)
  expect_gt(length(aud$high_density_rows), 0L)
  expect_gt(length(aud$warnings), 0L)
  expect_equal(nrow(aud$masked_previews), 5L)
  expect_output(print(aud), "airgap_pii_audit")

  # Verify ZERO raw synthetic PII leaked into previews, warnings, or printed output
  dump_txt <- paste(
    c(
      capture.output(print(aud)),
      aud$warnings,
      aud$masked_previews$redacted_preview
    ),
    collapse = "\n"
  )
  for (secret in c(
    "Jordan Ellis", "jordan.ellis@example.org", "123-45-6789",
    "012-3456", "92-year-old", "036xx", "Clara Vance", "scheduling@example.org"
  )) {
    expect_false(grepl(secret, dump_txt, fixed = TRUE), info = paste("Audit dry-run leaked:", secret))
  }
})

test_that("estimate_vram_requirements scales monotonically and recommends valid GPU tiers", {
  e_q4 <- estimate_vram_requirements(8, quantization = "Q4_K_M", context_length = 4096L, batch_size = 1L)
  e_q6 <- estimate_vram_requirements(8, quantization = "Q6_K", context_length = 4096L, batch_size = 1L)
  e_q8 <- estimate_vram_requirements(8, quantization = "Q8_0", context_length = 4096L, batch_size = 1L)
  e_fp16 <- estimate_vram_requirements(8, quantization = "FP16", context_length = 4096L, batch_size = 1L)

  expect_s3_class(e_q4, "airgap_vram_estimate")
  expect_lt(e_q4$weights_gb, e_q6$weights_gb)
  expect_lt(e_q6$weights_gb, e_q8$weights_gb)
  expect_lt(e_q8$weights_gb, e_fp16$weights_gb)
  expect_output(print(e_q4), "airgap_vram_estimate")

  # Longer context and larger batch increase KV cache monotonically
  e_long <- estimate_vram_requirements(8, quantization = "Q4_K_M", context_length = 32768L, batch_size = 4L)
  expect_gt(e_long$kv_cache_gb, e_q4$kv_cache_gb)
  expect_gt(e_long$total_vram_gb, e_q4$total_vram_gb)

  # KV cache quantization reduces KV VRAM
  e_kvq8 <- estimate_vram_requirements(8, quantization = "Q4_K_M", context_length = 32768L, batch_size = 4L, kv_cache_quant = "Q8_0")
  expect_lt(e_kvq8$kv_cache_gb, e_long$kv_cache_gb)

  # 70B FP16 requires multi-GPU tier
  e_70b <- estimate_vram_requirements(70, quantization = "FP16", context_length = 8192L, batch_size = 2L)
  expect_gt(e_70b$total_vram_gb, 120)
  expect_s3_class(e_70b$fits_tiers, "tbl_df")

  # Input validation
  expect_error(estimate_vram_requirements(-5), class = "airgap_validation_error")
  expect_error(estimate_vram_requirements(8, context_length = 32L), class = "airgap_validation_error")
})

test_that("pii_vault_rotate_key re-encrypts vaults atomically under a new key preserving re-identification", {
  k1 <- pii_vault_key()
  k2 <- pii_vault_key()
  vf <- withr::local_tempfile(fileext = ".vault.json")

  orig <- c(
    "Patient: Jordan Ellis (MRN: 000101) emailed jordan.ellis@example.org.",
    "Follow-up with Jordan Ellis via (555) 012-3456."
  )
  pse <- pii_pseudonymize(orig, key = k1, vault_path = vf, encrypt_vault = TRUE)
  env_before <- jsonlite::fromJSON(vf, simplifyVector = FALSE)

  rot <- pii_vault_rotate_key(vf, old_key = k1, new_key = k2, backup = TRUE)
  expect_true(file.exists(paste0(vf, ".bak")))
  on.exit(unlink(paste0(vf, ".bak")), add = TRUE)

  expect_false(identical(rot$old_key_fingerprint, rot$new_key_fingerprint))
  expect_equal(rot$n_tokens, length(pse$vault$mappings))

  env_after <- jsonlite::fromJSON(vf, simplifyVector = FALSE)
  expect_equal(env_after$format, "airgapllm_vault_v2")
  expect_false(identical(env_before$salt_b64, env_after$salt_b64))
  expect_false(identical(env_before$iv_b64, env_after$iv_b64))
  expect_false(identical(env_before$ciphertext_b64, env_after$ciphertext_b64))

  # Old key no longer decrypts rotated vault; new key restores original text losslessly
  expect_error(pii_vault_load(vf, key = k1), class = "airgap_vault_error")
  expect_identical(pii_reidentify(pse$text, vault = vf, key = k2), orig)

  # Same key rejected
  expect_error(pii_vault_rotate_key(vf, old_key = k2, new_key = k2), class = "airgap_key_error")
})

test_that("export_irb_compliance_packet builds a verified, SHA-256-sealed, zero-PII audit directory", {
  data("synthetic_notes", package = "airgapllm")
  sub_df <- synthetic_notes[1:5, ]

  spec <- airgap_container_spec(
    backend = "ollama",
    image_digest = paste0("sha256:", strrep("c", 64)),
    model_dir = "/srv/models/llama3",
    model_digest = paste0("sha256:", strrep("d", 64)),
    gpu = "nvidia"
  )
  sc <- extraction_schema(
    sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
    severity = schema_field("integer", min = 0L, max = 10L)
  )
  aud_log <- withr::local_tempfile(fileext = ".audit.jsonl")

  res <- airgap_extract(
    sub_df, "note_text", sc,
    runtime = runtime_mock(seed = 2026L),
    id_col = "note_id",
    container_spec = spec,
    audit_log_path = aud_log
  )

  pkt_dir <- file.path(withr::local_tempdir(), "irb_packet")
  pkt <- export_irb_compliance_packet(
    out_dir = pkt_dir,
    extraction = res,
    audit_log_path = aud_log,
    container_spec = spec,
    study_title = "Synthetic Clinical Reliability Study",
    protocol_id = "IRB-2026-088",
    institution = "University Research Center",
    regulatory_framework = c("HIPAA", "IRB")
  )

  expect_s3_class(pkt, "airgap_compliance_packet")
  expect_true(pkt$audit_valid)
  expect_output(print(pkt), "VERIFIED")
  expect_true(file.exists(file.path(pkt_dir, "packet_manifest.json")))
  expect_true(all(c(
    "audit_log.jsonl",
    "preflight_attestation.json",
    "container_docker_run.sh",
    "docker-compose.yml",
    "container_apptainer.def",
    "irb_protocol_narrative.md",
    "irb_protocol_narrative.qmd"
  ) %in% pkt$files$file))

  # Verify every file digest in packet_manifest.json matches actual disk bytes
  man <- jsonlite::fromJSON(file.path(pkt_dir, "packet_manifest.json"), simplifyVector = FALSE)
  expect_true(isTRUE(man$zero_pii_verified))
  for (f_rec in man$files) {
    actual_sha <- verify_model_digest(file.path(pkt_dir, f_rec$file))$actual_digest
    expect_identical(actual_sha, f_rec$sha256)
  }

  # Zero raw synthetic PII across ALL packet artifacts
  all_pkt_text <- paste(
    unlist(lapply(list.files(pkt_dir, full.names = TRUE), readLines, warn = FALSE)),
    collapse = "\n"
  )
  for (secret in c("Jordan Ellis", "jordan.ellis@example.org", "123-45-6789", "742 Oak Terrace", "036xx")) {
    expect_false(grepl(secret, all_pkt_text, fixed = TRUE), info = paste("Packet leaked:", secret))
  }

  # Refuses overwrite when overwrite = FALSE
  expect_error(
    export_irb_compliance_packet(pkt_dir, extraction = res, overwrite = FALSE),
    class = "airgap_validation_error"
  )
})

test_that("airgap_extract handles 0-row data frames and Windows-1252 / Latin-1 clinical exports safely", {
  sc <- extraction_schema(
    mood = schema_field("enum", values = c("calm", "anxious")),
    score = schema_field("integer", min = 0L, max = 10L)
  )

  # 1. 0-row data frame produces strictly typed 0-row airgap_extraction tibble
  empty_df <- tibble::tibble(id = character(), note = character())
  aud_empty <- withr::local_tempfile(fileext = ".audit.jsonl")
  res_empty <- airgap_extract(
    empty_df, "note", sc,
    runtime_mock(seed = 1L),
    id_col = "id",
    audit_log_path = aud_empty
  )
  expect_s3_class(res_empty, "airgap_extraction")
  expect_equal(nrow(res_empty), 0L)
  expect_true(is.character(res_empty$mood))
  expect_true(is.integer(res_empty$score))
  expect_equal(extraction_throughput(res_empty)$rows_total, 0L)
  expect_true(audit_log_verify(aud_empty)$valid)

  # 2. Windows-1252 smart quotes (0x92), em-dash (0x97), and Latin-1 e-acute (0xe9)
  cp1252_raw <- c(
    charToRaw("Patient: Jos"),
    as.raw(0xe9),
    charToRaw(" Alvarez"),
    as.raw(0x97),
    charToRaw("reported "),
    as.raw(0x93),
    charToRaw("mild stress"),
    as.raw(0x94),
    charToRaw(" via jose@example.org")
  )
  bad_enc_str <- rawToChar(cp1252_raw)
  Encoding(bad_enc_str) <- "unknown"

  df_enc <- tibble::tibble(id = "ENC_1", note = bad_enc_str)
  res_enc <- airgap_extract(df_enc, "note", sc, runtime_mock(seed = 3L), id_col = "id")
  expect_equal(res_enc$.status, "ok")
  expect_gte(extraction_privacy_report(res_enc)$total_entities, 1L)
})
