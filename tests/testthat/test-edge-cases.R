test_that("airgap_extract handles verified_deidentified, NA rows, retry_failed, and preserves .Random.seed", {
  set.seed(2026)
  seed_before <- .Random.seed

  df <- tibble::tibble(
    id = c("E1", "E2", "E3"),
    txt = c("Pre-deidentified clinical text.", NA_character_, "Another clean entry.")
  )
  sc <- extraction_schema(
    risk = schema_field("enum", values = c("low", "high")),
    score = schema_field("numeric", min = 0, max = 1)
  )

  res <- airgap_extract(
    df, "txt", sc,
    runtime_mock(seed = 12L),
    id_col = "id",
    pii_policy = "verified_deidentified"
  )
  expect_identical(.Random.seed, seed_before)
  expect_equal(res$.status, c("ok", "failed", "ok"))
  expect_match(res$.error[2L], "NA or empty")
  expect_equal(extraction_manifest(res)$pii_policy, "verified_deidentified")

  # Checkpoint retry_failed = TRUE re-attempts previously failed row
  ck <- withr::local_tempfile(fileext = ".jsonl")
  df2 <- tibble::tibble(id = c("A1", "A2"), txt = c("Text one.", "Text two."))
  r_fail <- airgap_extract(
    df2, "txt", sc,
    runtime_mock(seed = 5L, fail_rows = "A2"),
    id_col = "id",
    checkpoint_path = ck,
    max_retries = 0L
  )
  expect_equal(r_fail$.status, c("ok", "failed"))

  rt_retry <- runtime_mock(seed = 5L)
  r_fixed <- airgap_extract(
    df2, "txt", sc,
    rt_retry,
    id_col = "id",
    checkpoint_path = ck,
    resume = TRUE,
    retry_failed = TRUE
  )
  expect_equal(r_fixed$.status, c("ok", "ok"))
  called <- unique(vapply(rt_retry$state$call_log, `[[`, character(1L), "row_id"))
  expect_equal(called, "A2")

  # Duplicate / NA id_col values rejected
  df_dup <- tibble::tibble(id = c("X", "X"), txt = c("a", "b"))
  expect_error(airgap_extract(df_dup, "txt", sc, runtime_mock(), id_col = "id"), class = "airgap_validation_error")
})

test_that("PII config modes, unencrypted vaults, and audit edge cases work cleanly", {
  # detect_unlabeled_names = FALSE catches titled/role names but ignores plain capitalized pairs
  cfg_strict <- pii_config(detect_unlabeled_names = FALSE)
  txt <- "Dr. Jane Doe spoke with Maya Lin; Patient: Marcus Harris."
  det <- pii_detect(txt, config = cfg_strict)
  expect_true("Dr. Jane Doe" %in% det$match)
  expect_true("Marcus Harris" %in% det$match)
  expect_false("Maya Lin" %in% det$match)

  # Unencrypted vault roundtrip + unknown token left intact
  key <- pii_vault_key()
  vf <- withr::local_tempfile(fileext = ".plain.vault.json")
  p <- pii_pseudonymize("Contact bob@clinic.org.", key = key, vault_path = vf, encrypt_vault = FALSE)
  loaded <- pii_vault_load(vf)
  expect_s3_class(loaded, "airgap_pii_vault")
  unknown_str <- paste(p$text, "<<EMAIL_deadbeef00>>")
  expect_equal(pii_reidentify(unknown_str, loaded), "Contact bob@clinic.org. <<EMAIL_deadbeef00>>")

  # Audit verification handles nonexistent and empty files gracefully
  missing_log <- file.path(withr::local_tempdir(), "does-not-exist.jsonl")
  expect_false(audit_log_verify(missing_log)$valid)

  empty_log <- withr::local_tempfile(fileext = ".jsonl")
  file.create(empty_log)
  expect_false(audit_log_verify(empty_log)$valid)

  # Digest verification event + IRB narrative from manifest directly
  tmp_m <- withr::local_tempfile(fileext = ".gguf")
  writeBin(charToRaw("weights-bytes"), tmp_m)
  dv <- verify_model_digest(tmp_m)
  e_dv <- audit_log_append(empty_log, dv)
  expect_equal(e_dv$event_type, "model_verification")
  expect_true(audit_log_verify(empty_log)$valid)

  narr <- generate_irb_narrative(e_dv, regulatory_framework = "HIPAA")
  expect_s3_class(narr, "airgap_irb_narrative")
  expect_match(narr, dv$actual_digest, fixed = TRUE)
})
