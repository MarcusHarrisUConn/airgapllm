test_that("extraction_schema and validate_extraction enforce strict typing and constraints", {
  sc <- extraction_schema(
    sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
    severity = schema_field("integer", min = 0L, max = 10L),
    confidence = schema_field("numeric", min = 0, max = 1, nullable = TRUE),
    crisis = schema_field("logical"),
    code = schema_field("character", pattern = "^DX-[0-9]{3}$", min_length = 6L, max_length = 6L),
    name = "clinical_triage"
  )
  expect_s3_class(sc, "airgap_schema")
  expect_output(print(sc), "clinical_triage")

  js <- as_json_schema(sc)
  expect_equal(js$type, "object")
  expect_false(js$additionalProperties)
  expect_equal(js$properties$confidence$type, list("number", "null"))

  # Valid raw JSON (including fenced markdown JSON)
  good_json <- '{"sentiment":"negative","severity":7,"confidence":null,"crisis":true,"code":"DX-104"}'
  v_ok <- validate_extraction(good_json, sc)
  expect_true(v_ok$valid)
  expect_identical(v_ok$data$severity, 7L)
  expect_true(is.na(v_ok$data$confidence) && is.double(v_ok$data$confidence))
  expect_identical(v_ok$data$crisis, TRUE)

  fenced <- paste0("```json\n", good_json, "\n```")
  expect_true(validate_extraction(fenced, sc)$valid)

  # Malformed JSON
  expect_false(validate_extraction("{broken json", sc)$valid)
  # Non-object JSON array
  expect_false(validate_extraction("[1, 2, 3]", sc)$valid)
  # Missing field
  expect_false(validate_extraction('{"sentiment":"neutral"}', sc)$valid)
  # Extra key rejected when strict_keys = TRUE
  extra_json <- '{"sentiment":"neutral","severity":2,"confidence":0.8,"crisis":false,"code":"DX-001","extra":1}'
  expect_false(validate_extraction(extra_json, sc)$valid)
  # Non-nullable null rejected
  null_bad <- '{"sentiment":null,"severity":2,"confidence":0.8,"crisis":false,"code":"DX-001"}'
  expect_false(validate_extraction(null_bad, sc)$valid)
  # Wrong types & constraint violations
  type_bad <- '{"sentiment":"unknown","severity":3.5,"confidence":1.5,"crisis":"yes","code":"BAD"}'
  v_bad <- validate_extraction(type_bad, sc)
  expect_false(v_bad$valid)
  expect_gte(length(v_bad$errors), 5L)

  # Repair prompt incorporates diagnostics & schema
  rp <- build_repair_prompt("Extract note.", type_bad, v_bad$errors, sc)
  expect_match(rp, "REPAIR INSTRUCTION", fixed = TRUE)
  expect_match(rp, "sentiment", fixed = TRUE)
})

test_that("local HTTP runtimes reject remote URLs and use loopback + noproxy transport", {
  expect_error(
    runtime_ollama("llama3.1:8b", host = "https://remote-llm.example.com"),
    class = "airgap_isolation_error"
  )
  expect_error(
    runtime_openai_local("qwen2.5-7b", base_url = "https://api.openai.com/v1"),
    class = "airgap_isolation_error"
  )
  expect_error(
    runtime_openai_local("qwen2.5-7b", base_url = "http://127.0.0.1@evil.com/v1"),
    class = "airgap_isolation_error"
  )

  # Test Ollama request construction offline via httr2 mock transport
  seen_ollama <- list()
  ollama_rt <- runtime_ollama(
    model = "llama3.1:8b-q4",
    host = "http://127.0.0.1:11434",
    seed = 77L,
    temperature = 0,
    transport = function(req) {
      seen_ollama$url <<- req$url
      seen_ollama$options <<- req$options
      seen_ollama$body <<- req$body$data
      httr2::response_json(
        status_code = 200L,
        body = list(message = list(content = '{"label":"ok","score":8}'))
      )
    }
  )

  sc <- extraction_schema(
    label = schema_field("enum", values = c("ok", "alert")),
    score = schema_field("integer", min = 0L, max = 10L)
  )
  df <- tibble::tibble(id = "R1", txt = "Stable mood.")
  res_ol <- airgap_extract(df, "txt", sc, ollama_rt, id_col = "id")
  expect_equal(seen_ollama$url, "http://127.0.0.1:11434/api/chat")
  expect_equal(seen_ollama$options$noproxy, "*")
  expect_equal(seen_ollama$body$options$seed, 77L)
  expect_equal(res_ol$label, "ok")
  expect_identical(res_ol$score, 8L)

  # Test OpenAI-local (llama.cpp / vLLM) request construction offline via httr2 mock transport
  seen_oai <- list()
  oai_rt <- runtime_openai_local(
    model = "qwen2.5-7b-instruct",
    base_url = "http://127.0.0.1:8000/v1",
    seed = 99L,
    transport = function(req) {
      seen_oai$url <<- req$url
      seen_oai$options <<- req$options
      seen_oai$body <<- req$body$data
      httr2::response_json(
        status_code = 200L,
        body = list(choices = list(list(message = list(content = '{"label":"alert","score":9}'))))
      )
    }
  )
  res_oai <- airgap_extract(df, "txt", sc, oai_rt, id_col = "id")
  expect_equal(seen_oai$url, "http://127.0.0.1:8000/v1/chat/completions")
  expect_equal(seen_oai$options$noproxy, "*")
  expect_equal(seen_oai$body$seed, 99L)
  expect_equal(res_oai$label, "alert")
  expect_identical(res_oai$score, 9L)
})

test_that("airgap_extract enforces pre-inference PII redaction and pseudonymization before prompting", {
  df <- tibble::tibble(
    note_id = c("N1", "N2"),
    text = c(
      "Patient: Jane Doe (SSN 123-45-6789) emailed jane@clinic.org about insomnia.",
      "Dr. Robert Vance called (555) 987-6543 regarding anxiety."
    )
  )
  sc <- extraction_schema(
    theme = schema_field("character"),
    severity = schema_field("integer", min = 1L, max = 5L)
  )

  # 1. Redact policy: verify ZERO raw PII reaches runtime prompts
  rt_red <- runtime_mock(seed = 10L)
  res_red <- airgap_extract(df, "text", sc, rt_red, id_col = "note_id", pii_policy = "redact")
  expect_s3_class(res_red, "airgap_extraction")
  expect_s3_class(res_red, "tbl_df")
  expect_true(is.character(res_red$theme))
  expect_true(is.integer(res_red$severity))
  expect_equal(res_red$.status, c("ok", "ok"))

  all_prompts_red <- paste(vapply(rt_red$state$call_log, `[[`, character(1L), "prompt"), collapse = "\n")
  for (secret in c("Jane Doe", "123-45-6789", "jane@clinic.org", "Robert Vance", "987-6543")) {
    expect_false(grepl(secret, all_prompts_red, fixed = TRUE), info = paste("Prompt leaked:", secret))
  }
  expect_match(all_prompts_red, "\\[REDACTED_PERSON_NAME\\]")
  expect_match(all_prompts_red, "\\[REDACTED_SSN\\]")

  # 2. Pseudonymize policy + encrypted vault + local re-identification of output
  key <- pii_vault_key()
  vf <- withr::local_tempfile(fileext = ".vault.json")
  rt_pse <- runtime_mock(
    handler = function(prompt, row_id, attempt, schema) {
      # Echo the first pseudonym token from prompt into the theme field to test re-identification
      m <- regmatches(prompt, regexpr("<<PERSON_NAME_[0-9a-f]{10}>>", prompt))
      list(theme = paste("Summary for", m), severity = 3L)
    }
  )
  res_pse <- airgap_extract(
    df, "text", sc, rt_pse,
    id_col = "note_id",
    pii_policy = "pseudonymize",
    pii_key = key,
    vault_path = vf,
    reidentify_output = TRUE
  )
  expect_true(file.exists(vf))
  expect_s3_class(extraction_vault(res_pse), "airgap_pii_vault")
  # Prompts sent to model had NO raw names
  all_prompts_pse <- paste(vapply(rt_pse$state$call_log, `[[`, character(1L), "prompt"), collapse = "\n")
  expect_false(grepl("Jane Doe", all_prompts_pse, fixed = TRUE))
  expect_false(grepl("Robert Vance", all_prompts_pse, fixed = TRUE))
  # Local re-identified output restored names cleanly
  expect_equal(res_pse$theme[1L], "Summary for Jane Doe")
  expect_equal(res_pse$theme[2L], "Summary for Dr. Robert Vance")

  # Missing pii_key for pseudonymize errors
  expect_error(
    airgap_extract(df, "text", sc, runtime_mock(), pii_policy = "pseudonymize"),
    class = "airgap_key_error"
  )
})

test_that("airgap_extract performs structured repair retries on malformed outputs", {
  df <- tibble::tibble(
    id = c("R1", "R2", "R3"),
    txt = c("Note one.", "Note two.", "Note three.")
  )
  sc <- extraction_schema(
    mood = schema_field("enum", values = c("calm", "anxious", "depressed")),
    score = schema_field("integer", min = 0L, max = 10L)
  )

  rt <- runtime_mock(
    seed = 42L,
    malform_schedule = list(
      R1 = c(
        "{not valid json at all",
        '{"mood": "ecstatic", "score": 99}'
      )
    ),
    fail_rows = "R3"
  )

  res <- airgap_extract(df, "txt", sc, rt, id_col = "id", max_retries = 2L)

  # R1 fails attempts 1 & 2, succeeds on attempt 3 via repair prompt
  expect_equal(res$.status, c("ok", "ok", "failed"))
  expect_equal(res$.attempts, c(3L, 1L, 3L))
  expect_true(res$mood[1L] %in% c("calm", "anxious", "depressed"))
  expect_true(is.na(res$mood[3L]))
  expect_true(is.na(res$score[3L]))
  expect_match(res$.error[3L], "Malformed JSON")

  # Verify repair prompt sent on R1 attempt 3 explicitly cited enum & max error
  r1_calls <- Filter(function(x) identical(x$row_id, "R1"), rt$state$call_log)
  expect_length(r1_calls, 3L)
  expect_match(r1_calls[[2L]]$prompt, "REPAIR INSTRUCTION", fixed = TRUE)
  expect_match(r1_calls[[3L]]$prompt, "ecstatic", fixed = TRUE)
  expect_match(r1_calls[[3L]]$prompt, "exceeds max", fixed = TRUE)

  tp <- extraction_throughput(res)
  expect_equal(tp$rows_succeeded, 2L)
  expect_equal(tp$rows_failed, 1L)
  expect_equal(tp$total_retries, 4L)
})

test_that("airgap_extract checkpointing resumes cleanly after mid-batch crash and partial writes", {
  df <- tibble::tibble(
    doc_id = sprintf("D%02d", 1:10),
    text = paste("Patient: Alice Smith (alice@med.org) entry number", 1:10)
  )
  sc <- extraction_schema(
    category = schema_field("enum", values = c("A", "B", "C")),
    rating = schema_field("integer", min = 1L, max = 5L),
    flag = schema_field("logical")
  )

  # Baseline uninterrupted run
  baseline <- airgap_extract(df, "text", sc, runtime_mock(seed = 101L), id_col = "doc_id")

  # Simulated crash after 4 rows
  ck_file <- withr::local_tempfile(fileext = ".checkpoint.jsonl")
  rt_crash <- runtime_mock(seed = 101L, crash_after = 4L)
  expect_error(
    airgap_extract(df, "text", sc, rt_crash, id_col = "doc_id", checkpoint_path = ck_file),
    class = "airgap_simulated_crash"
  )

  # Checkpoint contains header + 4 committed rows, and ZERO raw PII
  ck_lines <- readLines(ck_file, warn = FALSE)
  expect_equal(length(ck_lines), 5L)
  ck_blob <- paste(ck_lines, collapse = "\n")
  expect_false(grepl("Alice Smith", ck_blob, fixed = TRUE))
  expect_false(grepl("alice@med.org", ck_blob, fixed = TRUE))
  expect_false(grepl("entry number", ck_blob, fixed = TRUE))

  # Simulate hard power-loss partial JSON write at end of checkpoint file
  cat('{"record_type":"row","row_id":"D05","status":"o', file = ck_file, append = TRUE)

  # Resume run: recovers partial line with warning and processes ONLY rows D05..D10
  rt_resume <- runtime_mock(seed = 101L)
  expect_warning(
    resumed <- airgap_extract(
      df, "text", sc, rt_resume,
      id_col = "doc_id",
      checkpoint_path = ck_file,
      resume = TRUE
    ),
    "truncated trailing checkpoint"
  )

  # Verify D01..D04 were NOT re-sent to runtime
  called_ids <- unique(vapply(rt_resume$state$call_log, `[[`, character(1L), "row_id"))
  expect_equal(called_ids, sprintf("D%02d", 5:10))

  tp <- extraction_throughput(resumed)
  expect_equal(tp$rows_resumed, 4L)
  expect_equal(tp$rows_processed, 6L)
  expect_equal(tp$rows_succeeded, 10L)

  # Extracted schema values match uninterrupted baseline identically
  expect_identical(resumed$doc_id, baseline$doc_id)
  expect_identical(resumed$category, baseline$category)
  expect_identical(resumed$rating, baseline$rating)
  expect_identical(resumed$flag, baseline$flag)

  # Attempting to resume into a mismatched schema fails loudly
  other_schema <- extraction_schema(other_col = schema_field("character"))
  expect_error(
    airgap_extract(df, "text", other_schema, runtime_mock(), id_col = "doc_id", checkpoint_path = ck_file, resume = TRUE),
    class = "airgap_checkpoint_error"
  )
})
