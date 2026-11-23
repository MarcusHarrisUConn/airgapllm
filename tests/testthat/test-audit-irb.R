test_that("audit_log_append and audit_log_verify maintain a tamper-evident hash chain", {
  log_file <- withr::local_tempfile(fileext = ".audit.jsonl")
  spec <- airgap_container_spec(
    backend = "ollama",
    image_digest = paste0("sha256:", strrep("a", 64)),
    model_dir = "/srv/models"
  )
  sc <- extraction_schema(
    label = schema_field("enum", values = c("low", "high")),
    score = schema_field("integer", min = 0L, max = 5L)
  )
  df <- tibble::tibble(
    id = c("P1", "P2"),
    note = c(
      "Patient: Clara Oswald (MRN: 551029) emailed clara@clinic.org.",
      "SSN 123-45-6789 on file; mood stable."
    )
  )

  # Entry 1 via airgap_extract auto-logging
  res1 <- airgap_extract(
    df, "note", sc, runtime_mock(seed = 1L),
    id_col = "id",
    container_spec = spec,
    audit_log_path = log_file
  )
  # Entry 2: preflight check record
  pf <- preflight_isolation_check(spec = spec, endpoint = "http://127.0.0.1:11434")
  e2 <- audit_log_append(log_file, pf, metadata = list(irb_protocol = "IRB-2026-0412"))
  # Entry 3: second extraction run
  res3 <- airgap_extract(
    df, "note", sc, runtime_mock(seed = 2L),
    id_col = "id",
    container_spec = spec,
    audit_log_path = log_file
  )

  expect_s3_class(e2, "airgap_audit_entry")
  expect_output(print(e2), "airgap_audit_entry")

  ver <- audit_log_verify(log_file)
  expect_s3_class(ver, "airgap_audit_verification")
  expect_true(ver$valid)
  expect_equal(ver$n_entries, 3L)
  expect_true(is.na(ver$first_invalid_seq))
  expect_match(ver$chain_head_hash, "^sha256:[0-9a-f]{64}$")
  expect_output(print(ver), "VALID")

  # Read log summary
  log_obj <- audit_log_read(log_file)
  expect_s3_class(log_obj, "airgap_audit_log")
  expect_equal(nrow(log_obj$summary), 3L)
  expect_equal(log_obj$summary$seq, 1:3)
  expect_equal(log_obj$entries[[1L]]$prev_hash, "GENESIS")
  expect_equal(log_obj$entries[[2L]]$prev_hash, log_obj$entries[[1L]]$entry_hash)
  expect_equal(log_obj$entries[[3L]]$prev_hash, log_obj$entries[[2L]]$entry_hash)

  # Zero raw PII or raw input text anywhere in the audit log bytes
  raw_log <- paste(readLines(log_file, warn = FALSE), collapse = "\n")
  for (secret in c("Clara Oswald", "551029", "clara@clinic.org", "123-45-6789", "mood stable")) {
    expect_false(grepl(secret, raw_log, fixed = TRUE), info = paste("Audit log leaked:", secret))
  }

  # Tamper test 1: edit a field inside line 2
  lines <- readLines(log_file, warn = FALSE)
  tampered1 <- withr::local_tempfile(fileext = ".jsonl")
  lines_mod <- lines
  lines_mod[2L] <- sub("IRB-2026-0412", "IRB-2026-9999", lines_mod[2L], fixed = TRUE)
  writeLines(lines_mod, tampered1)
  v_t1 <- audit_log_verify(tampered1)
  expect_false(v_t1$valid)
  expect_equal(v_t1$first_invalid_seq, 2L)
  expect_output(print(v_t1), "TAMPERED")

  # Appending to tampered log fails closed
  expect_error(
    audit_log_append(tampered1, res1, verify_existing = TRUE),
    class = "airgap_audit_tamper_error"
  )

  # Tamper test 2: delete middle entry (#2)
  tampered2 <- withr::local_tempfile(fileext = ".jsonl")
  writeLines(lines[c(1L, 3L)], tampered2)
  v_t2 <- audit_log_verify(tampered2)
  expect_false(v_t2$valid)
  expect_equal(v_t2$first_invalid_seq, 2L)

  # Tamper test 3: reorder lines
  tampered3 <- withr::local_tempfile(fileext = ".jsonl")
  writeLines(lines[c(2L, 1L, 3L)], tampered3)
  v_t3 <- audit_log_verify(tampered3)
  expect_false(v_t3$valid)
  expect_equal(v_t3$first_invalid_seq, 1L)
})

test_that("audit_log_append enforces strict zero-PII-leakage invariants", {
  log_file <- withr::local_tempfile(fileext = ".jsonl")

  # Forbidden raw text keys at top level or nested
  expect_error(
    audit_log_append(log_file, list(run_id = "r1", raw_text = "patient notes")),
    class = "airgap_audit_privacy_error"
  )
  expect_error(
    audit_log_append(log_file, list(run_id = "r1", prompt = "system prompt")),
    class = "airgap_audit_privacy_error"
  )
  expect_error(
    audit_log_append(log_file, list(run_id = "r1"), metadata = list(notes = "free text")),
    class = "airgap_audit_privacy_error"
  )

  # Undeclared top-level keys rejected
  expect_error(
    audit_log_append(log_file, list(run_id = "r1", custom_blob = "anything")),
    class = "airgap_audit_privacy_error"
  )

  # Non-integer / string values in pii_counts rejected
  expect_error(
    audit_log_append(log_file, list(run_id = "r1", pii_counts = list(email = "jane@clinic.org"))),
    class = "airgap_audit_privacy_error"
  )

  # PII inside metadata string rejected
  expect_error(
    audit_log_append(log_file, list(run_id = "r1"), metadata = list(contact = "jane@clinic.org")),
    class = "airgap_audit_privacy_error"
  )
  expect_error(
    audit_log_append(log_file, list(run_id = "r1"), metadata = list(tag = "123-45-6789")),
    class = "airgap_audit_privacy_error"
  )
  expect_error(
    audit_log_append(log_file, list(run_id = "r1"), metadata = list(blob = strrep("a", 300L))),
    class = "airgap_audit_privacy_error"
  )
})

test_that("generate_irb_narrative renders verified Markdown and Quarto protocols without PII", {
  log_file <- withr::local_tempfile(fileext = ".audit.jsonl")
  spec <- airgap_container_spec(
    backend = "llama.cpp",
    image_digest = paste0("sha256:", strrep("7", 64)),
    model_dir = "/srv/models",
    model_file = "llama-3.1-8b-q4.gguf",
    model_digest = paste0("sha256:", strrep("8", 64))
  )
  sc <- extraction_schema(
    distress = schema_field("enum", values = c("none", "mild", "severe")),
    rating = schema_field("integer", min = 0L, max = 10L)
  )
  df <- tibble::tibble(
    id = c("S1", "S2"),
    journal = c(
      "Dr. Hannah Abbott spoke with student at hannah@school.edu on 2026-03-01.",
      "Homework completed; calm affect."
    )
  )

  key <- pii_vault_key()
  res <- airgap_extract(
    df, "journal", sc,
    runtime_mock(seed = 55L),
    id_col = "id",
    pii_policy = "pseudonymize",
    pii_key = key,
    container_spec = spec,
    audit_log_path = log_file
  )

  # From extraction result (Markdown)
  md <- generate_irb_narrative(
    res,
    study_title = "Longitudinal Student Wellbeing Study",
    protocol_id = "IRB-2026-099",
    institution = "University of Connecticut",
    regulatory_framework = c("IRB", "FERPA"),
    format = "markdown"
  )
  expect_s3_class(md, "airgap_irb_narrative")
  expect_match(md, "Longitudinal Student Wellbeing Study", fixed = TRUE)
  expect_match(md, "IRB-2026-099", fixed = TRUE)
  expect_match(md, "IRB / FERPA", fixed = TRUE)
  expect_match(md, "HMAC-SHA256", fixed = TRUE)
  expect_match(md, "AES-256-CBC", fixed = TRUE)
  expect_match(md, strrep("7", 64), fixed = TRUE)
  expect_match(md, strrep("8", 64), fixed = TRUE)
  expect_match(md, "`email`", fixed = TRUE)
  expect_match(md, "`person_name`", fixed = TRUE)
  expect_output(print(md), "Data Security")

  # Verify ZERO raw PII or raw journal prose leaked into narrative
  for (secret in c("Hannah Abbott", "hannah@school.edu", "2026-03-01", "Homework completed")) {
    expect_false(grepl(secret, md, fixed = TRUE), info = paste("IRB narrative leaked:", secret))
  }

  # From verified audit log file path (Quarto format + save to file)
  qmd_path <- withr::local_tempfile(fileext = ".qmd")
  qmd <- generate_irb_narrative(
    log_file,
    protocol_id = "IRB-2026-099",
    format = "quarto",
    file = qmd_path
  )
  expect_true(file.exists(qmd_path))
  expect_match(qmd, ":::\\s*\\{\\.callout-note", perl = TRUE)
  expect_match(qmd, "VERIFIED", fixed = TRUE)

  # Refuses to render from a tampered audit log
  lines <- readLines(log_file, warn = FALSE)
  lines[1L] <- sub("llama.cpp", "tampered", lines[1L], fixed = TRUE)
  writeLines(lines, log_file)
  expect_error(
    generate_irb_narrative(log_file),
    class = "airgap_audit_tamper_error"
  )
})
