# Targeted Coverage-Gap & Latent-Bug Regression Tests (v0.4.0)

test_that("latent bug regressions: 0-byte checkpoint header, pseudonym output leak, and malformed audit tail", {
  sc <- extraction_schema(
    summary = schema_field("character"),
    label = schema_field("enum", values = c("ok", "alert"))
  )

  # 1. Latent Bug Fix: pre-existing 0-byte checkpoint file gets header written and resumes cleanly
  df <- tibble::tibble(id = c("R1", "R2"), txt = c("Clean entry one.", "Clean entry two."))
  empty_ck <- withr::local_tempfile(fileext = ".jsonl")
  file.create(empty_ck)
  res1 <- airgap_extract(df[1L, ], "txt", sc, runtime_mock(seed = 5L), id_col = "id", checkpoint_path = empty_ck, resume = TRUE)
  expect_equal(res1$.status, "ok")
  res2 <- airgap_extract(df, "txt", sc, runtime_mock(seed = 5L), id_col = "id", checkpoint_path = empty_ck, resume = TRUE)
  expect_equal(extraction_throughput(res2)$rows_resumed, 1L)
  expect_equal(extraction_throughput(res2)$rows_processed, 1L)

  # resume = FALSE overwrites existing checkpoint cleanly
  res_fresh <- airgap_extract(df, "txt", sc, runtime_mock(seed = 5L), id_col = "id", checkpoint_path = empty_ck, resume = FALSE, progress = TRUE)
  expect_equal(extraction_throughput(res_fresh)$rows_resumed, 0L)

  # 2. Latent Bug Fix: pseudonymize + raw PII leak in model output preserves <<TYPE_HASH>> token while scrubbing leak
  key <- pii_vault_key()
  df_p <- tibble::tibble(id = "P1", txt = "Patient: Jane Doe reported calm mood.")
  rt_mixed <- runtime_mock(
    handler = function(prompt, row_id, attempt, schema) {
      tok <- regmatches(prompt, regexpr("<<PERSON_NAME_[0-9a-f]{10}>>", prompt))
      list(
        summary = paste("Record for", tok, "leaked secret@evil.org and SSN 123-45-6789."),
        label = "ok"
      )
    }
  )
  res_p <- airgap_extract(
    df_p, "txt", sc, rt_mixed,
    id_col = "id",
    pii_policy = "pseudonymize",
    pii_key = key,
    reidentify_output = TRUE,
    output_pii_action = "redact"
  )
  expect_match(res_p$summary, "Jane Doe", fixed = TRUE)
  expect_false(grepl("secret@evil.org", res_p$summary, fixed = TRUE))
  expect_false(grepl("123-45-6789", res_p$summary, fixed = TRUE))
  expect_gte(extraction_throughput(res_p)$output_pii_leaks, 2L)

  # Custom prompt_template without {text} or delimiters still wraps safely
  rt_cap <- runtime_mock(seed = 1L)
  airgap_extract(df[1L, ], "txt", sc, rt_cap, id_col = "id", prompt_template = "Analyze clinical record:")
  expect_match(rt_cap$state$call_log[[1L]]$prompt, "<UNTRUSTED_RESEARCH_RECORD>", fixed = TRUE)

  # 3. Latent Bug Fix: audit_log_append(verify_existing = FALSE) rejects malformed tail missing seq/entry_hash
  bad_tail_log <- withr::local_tempfile(fileext = ".jsonl")
  writeLines('{"broken":true}', bad_tail_log)
  expect_error(
    audit_log_append(bad_tail_log, list(run_id = "r1"), verify_existing = FALSE),
    class = "airgap_audit_tamper_error"
  )
})

test_that("schema, utils, security, and vault v1/v2 validation branches are thoroughly exercised", {
  # Utils: raw keys (<16 bytes rejected, 16-byte raw accepted & hashed, passphrase hashed)
  expect_error(airgapllm:::normalize_secret_key(raw(8)), class = "airgap_key_error")
  expect_length(airgapllm:::normalize_secret_key(openssl::rand_bytes(16L)), 32L)
  expect_length(airgapllm:::normalize_secret_key("passphrase-key"), 32L)
  expect_error(airgapllm:::normalize_secret_key(123), class = "airgap_key_error")
  expect_null(airgapllm:::normalize_sha256_digest(NULL, allow_null = TRUE))
  expect_error(airgapllm:::normalize_sha256_digest(NULL, allow_null = FALSE), class = "airgap_digest_error")
  expect_error(airgapllm:::normalize_sha256_digest(123), class = "airgap_digest_error")
  expect_equal(airgapllm:::sha256_string(NA_character_), airgapllm:::sha256_string(""))

  # Security: HKDF validation & constant_time_equal edge cases
  expect_error(airgapllm:::hkdf_sha256(raw(0)), class = "airgap_key_error")
  expect_error(airgapllm:::hkdf_sha256(openssl::rand_bytes(16), length = 0L), class = "airgap_key_error")
  expect_length(airgapllm:::hkdf_sha256(openssl::rand_bytes(16), salt = NULL, info = "test", length = 32L), 32L)
  expect_false(airgapllm:::constant_time_equal(123, "abc"))
  expect_false(airgapllm:::constant_time_equal("abc", 123))
  expect_true(airgapllm:::constant_time_equal("", ""))

  # Schema field & extraction_schema validation branches
  expect_error(schema_field("enum", values = character()), class = "airgap_validation_error")
  expect_error(schema_field("character", values = c("a")), class = "airgap_validation_error")
  expect_error(schema_field("character", min = 1), class = "airgap_validation_error")
  expect_error(schema_field("integer", min = Inf), class = "airgap_validation_error")
  expect_error(schema_field("integer", max = Inf), class = "airgap_validation_error")
  expect_error(schema_field("integer", min = 10, max = 5), class = "airgap_validation_error")
  expect_error(schema_field("integer", pattern = "^a"), class = "airgap_validation_error")
  expect_error(schema_field("character", pattern = "[unclosed"), class = "airgap_validation_error")
  expect_error(schema_field("integer", min_length = 1L), class = "airgap_validation_error")
  expect_error(schema_field("character", min_length = -1L), class = "airgap_validation_error")
  expect_error(schema_field("character", max_length = 0L), class = "airgap_validation_error")
  expect_error(schema_field("character", min_length = 5L, max_length = 3L), class = "airgap_validation_error")

  # List-of-fields constructor + schema errors + validation edge cases
  sc_list <- extraction_schema(
    list(
      txt = schema_field("character", description = "Short text", max_length = 5L),
      n = schema_field("integer", min = 2L, max = 5L),
      x = schema_field("numeric", min = 0.5, max = 2.0),
      e = schema_field("enum", values = c("a", "b"))
    ),
    description = "Demo schema"
  )
  js <- as_json_schema(sc_list)
  expect_equal(js$description, "Demo schema")
  expect_equal(js$properties$txt$description, "Short text")

  expect_error(extraction_schema(), class = "airgap_validation_error")
  expect_error(extraction_schema(schema_field("character")), class = "airgap_validation_error")
  expect_error(extraction_schema(a = schema_field("character"), a = schema_field("integer")), class = "airgap_validation_error")
  expect_error(extraction_schema(.status = schema_field("character")), class = "airgap_validation_error")
  expect_error(extraction_schema(a = "not_a_field"), class = "airgap_validation_error")
  expect_error(as_json_schema("bad"), class = "airgap_validation_error")
  expect_error(validate_extraction("{}", "bad"), class = "airgap_validation_error")
  expect_error(build_repair_prompt("p", "o", "e", "bad"), class = "airgap_validation_error")

  expect_false(validate_extraction("", sc_list)$valid)
  expect_false(validate_extraction(list(txt = c("a", "b"), n = 3L, x = 1, e = "a"), sc_list)$valid)
  expect_false(validate_extraction(list(txt = 123, n = 1L, x = "bad", e = 5), sc_list)$valid)
  expect_false(validate_extraction(list(txt = "toolong", n = 3L, x = 0.1, e = "a"), sc_list)$valid)
  expect_match(build_repair_prompt("p", NA_character_, "err", sc_list), "<empty>", fixed = TRUE)
  expect_match(build_repair_prompt("p", strrep("x", 1500L), "err", sc_list), "truncated", fixed = TRUE)

  # Legacy vault v1 backward-compatible decryption via constant-time MAC check
  key <- pii_vault_key()
  master <- airgapllm:::normalize_secret_key(key)
  enc_key <- as.raw(openssl::sha256(c(master, charToRaw("|airgapllm-vault-enc-v1"))))
  mac_key <- as.raw(openssl::sha256(c(master, charToRaw("|airgapllm-vault-mac-v1"))))
  iv <- openssl::rand_bytes(16L)
  payload <- airgapllm:::canonical_json(list(
    vault_id = "legacy_v1",
    key_fingerprint = "abcd1234abcd1234",
    created_at = "2026-01-01T00:00:00Z",
    mappings = list("<<EMAIL_1234567890>>" = list(entity_type = "email", value = "old@example.org"))
  ))
  ct <- openssl::aes_cbc_encrypt(charToRaw(payload), key = enc_key, iv = iv)
  mac <- airgapllm:::hash_to_hex(openssl::sha256(c(iv, ct), key = mac_key))
  v1_file <- withr::local_tempfile(fileext = ".v1.json")
  writeLines(jsonlite::toJSON(list(
    format = "airgapllm_vault_v1",
    encrypted = TRUE,
    cipher = "aes-256-cbc-hmac-sha256",
    vault_id = "legacy_v1",
    key_fingerprint = "abcd1234abcd1234",
    iv_b64 = openssl::base64_encode(iv),
    ciphertext_b64 = openssl::base64_encode(ct),
    mac_hex = mac
  ), auto_unbox = TRUE), v1_file)
  loaded_v1 <- pii_vault_load(v1_file, key = key)
  expect_equal(loaded_v1$vault_id, "legacy_v1")
  expect_equal(pii_reidentify("Contact <<EMAIL_1234567890>>", loaded_v1), "Contact old@example.org")
})

test_that("audit, checkpoint, runtime, container, and workflow edge-case branches are covered", {
  # Audit log edge cases: empty log read, print, verify malformed/forbidden/undeclared/missing hash, PII in run_id
  empty_aud <- withr::local_tempfile(fileext = ".jsonl")
  file.create(empty_aud)
  al_empty <- audit_log_read(empty_aud)
  expect_equal(nrow(al_empty$summary), 0L)
  expect_output(print(al_empty), "0 entries")

  expect_error(audit_log_read(file.path(tempdir(), "no_such_audit_file_999.jsonl")), class = "airgap_audit_error")
  expect_error(audit_log_append(empty_aud, list(run_id = "user@example.org")), class = "airgap_audit_privacy_error")
  expect_error(audit_log_append(empty_aud, list(run_id = "r1", output_pii_leaks = -1)), class = "airgap_audit_privacy_error")
  expect_error(audit_log_append(empty_aud, list(run_id = "r1", pii_counts = "bad")), class = "airgap_audit_privacy_error")
  expect_error(audit_log_append(empty_aud, list(run_id = "r1"), metadata = "not_list"), class = "airgap_validation_error")

  bad_aud <- withr::local_tempfile(fileext = ".jsonl")
  writeLines(c(
    "{not_json",
    '{"seq":2,"prev_hash":"GENESIS","raw_text":"leak","extra_col":1,"entry_hash":"not_a_sha"}'
  ), bad_aud)
  v_bad <- audit_log_verify(bad_aud, strict = TRUE)
  expect_false(v_bad$valid)
  expect_gte(length(v_bad$issues), 4L)

  # Checkpoint mismatch branches (prompt hash mismatch, pii_policy mismatch, missing header)
  sc <- extraction_schema(a = schema_field("character"))
  df <- tibble::tibble(id = "1", txt = "Clean note.")
  ck <- withr::local_tempfile(fileext = ".jsonl")
  airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id", checkpoint_path = ck, prompt_template = "Prompt A: {text}")
  expect_error(
    airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id", checkpoint_path = ck, prompt_template = "Prompt B: {text}"),
    class = "airgap_checkpoint_error"
  )
  expect_error(
    airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id", checkpoint_path = ck, prompt_template = "Prompt A: {text}", pii_policy = "verified_deidentified"),
    class = "airgap_checkpoint_error"
  )
  ck_nohdr <- withr::local_tempfile(fileext = ".jsonl")
  writeLines('{"record_type":"row","row_id":"1"}', ck_nohdr)
  expect_error(
    airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id", checkpoint_path = ck_nohdr),
    class = "airgap_checkpoint_error"
  )

  # Runtime & PII & workflow print/helper edge cases
  expect_output(print(runtime_mock()), "airgap_runtime:mock")
  expect_output(print(pii_config()), "airgap_pii_config")
  key <- pii_vault_key()
  pse <- pii_pseudonymize("Email a@example.org", key = key)
  expect_output(print(pse), "airgap_pseudonymized")
  expect_s3_class(pii_privacy_report(pse), "airgap_privacy_report")
  expect_equal(pii_reidentify(pse$text, pse), "Email a@example.org")

  # Preflight with existing model file but no pinned expected digest fails
  tmp_m <- withr::local_tempfile(fileext = ".gguf")
  writeBin(charToRaw("weights"), tmp_m)
  pf_unpinned <- preflight_isolation_check(model_path = tmp_m)
  expect_false(pf_unpinned$passed)

  # Workflow: chunk_clinical_texts whitespace fallback + VRAM all parameter tiers + n_layers override
  no_punct <- tibble::tibble(txt = paste(rep("wordtoken", 30), collapse = " "))
  ch_ws <- chunk_clinical_texts(no_punct, "txt", max_chars = 80L, overlap_chars = 15L, split_on = "sentence")
  expect_gt(nrow(ch_ws), 1L)

  expect_equal(estimate_vram_requirements(3)$n_layers, 28L)
  expect_equal(estimate_vram_requirements(14)$n_layers, 40L)
  expect_equal(estimate_vram_requirements(32)$n_layers, 64L)
  expect_equal(estimate_vram_requirements(8, n_layers = 36L)$n_layers, 36L)
  expect_match(estimate_vram_requirements(120, quantization = "FP16")$recommended_gpu_tier, "Multi-GPU")

  # Compliance packet from tampered audit log rejected; unpinned container spec warns
  tampered <- withr::local_tempfile(fileext = ".jsonl")
  writeLines('{"seq":1,"prev_hash":"GENESIS","entry_hash":"bad"}', tampered)
  expect_error(
    export_irb_compliance_packet(file.path(withr::local_tempdir(), "pkt"), audit_log_path = tampered),
    class = "airgap_audit_tamper_error"
  )
  res_ok <- airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id")
  expect_warning(
    export_irb_compliance_packet(
      file.path(withr::local_tempdir(), "pkt_unpin"),
      extraction = res_ok,
      container_spec = airgap_container_spec(backend = "ollama")
    ),
    "unpinned"
  )
})
