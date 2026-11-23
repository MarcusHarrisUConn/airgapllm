test_that("pii_detect and pii_redact handle all built-in PII entity classes accurately", {
  samples <- c(
    "Email Dr. Jane Doe at jane.doe+lab@clinic.uconn.edu regarding follow-up.",
    "SSN: 123-45-6789 and backup SSN 987 65 4321; invalid 000-11-2222 ignored.",
    "Call (555) 234-5678 ext. 42 or +1-800-555-0199 or +44 20 7946 0958.",
    "DOB: 1988-03-15; visited on 04/12/2026 and March 15, 2025 (25/12/2024).",
    "Patient ID: PT-884210 and MRN: 9920145 and Student ID #STU-44102.",
    "Logged from 192.168.10.42 and 2001:db8::1 (not 999.999.1.1).",
    "Lives at 742 Evergreen Terrace, Apt 4B, Hartford, CT 06103 or P.O. Box 902.",
    "Patient: Sarah O'Connor met with Prof. Marcus Harris and Jean-Luc Picard."
  )

  det <- pii_detect(samples)
  expect_s3_class(det, "tbl_df")

  # Check every built-in entity type was caught
  expect_true(all(pii_default_entities() %in% det$entity_type))

  # Specific edge cases
  expect_true("jane.doe+lab@clinic.uconn.edu" %in% det$match[det$entity_type == "email"])
  expect_true("123-45-6789" %in% det$match[det$entity_type == "ssn"])
  expect_false("000-11-2222" %in% det$match[det$entity_type == "ssn"])
  expect_true(any(grepl("555\\) 234-5678", det$match[det$entity_type == "phone"])))
  expect_true(any(grepl("\\+44 20 7946 0958", det$match[det$entity_type == "phone"])))
  expect_true("192.168.10.42" %in% det$match[det$entity_type == "ip_address"])
  expect_true("2001:db8::1" %in% det$match[det$entity_type == "ip_address"])
  expect_false("999.999.1.1" %in% det$match[det$entity_type == "ip_address"])
  expect_true(any(grepl("742 Evergreen Terrace", det$match[det$entity_type == "street_address"])))
  expect_true("P.O. Box 902" %in% det$match[det$entity_type == "street_address"])
  expect_true("Sarah O'Connor" %in% det$match[det$entity_type == "person_name"])
  expect_true("Prof. Marcus Harris" %in% det$match[det$entity_type == "person_name"])
  expect_true("Jean-Luc Picard" %in% det$match[det$entity_type == "person_name"])

  # Redaction removes all sensitive substrings
  red <- pii_redact(samples)
  joined_red <- paste(red, collapse = "\n")
  for (secret in c(
    "jane.doe+lab@clinic.uconn.edu", "123-45-6789", "234-5678",
    "7946 0958", "1988-03-15", "884210", "192.168.10.42",
    "Evergreen Terrace", "Sarah O'Connor", "Marcus Harris"
  )) {
    expect_false(grepl(secret, joined_red, fixed = TRUE), info = paste("Leaked:", secret))
  }
  expect_match(red[1L], "\\[REDACTED_PERSON_NAME\\]")
  expect_match(red[1L], "\\[REDACTED_EMAIL\\]")
  expect_s3_class(attr(red, "pii_report"), "airgap_privacy_report")
})

test_that("overlap priority, stopwords, custom patterns, custom dictionaries, and allowlist work", {
  # "Dr." as street suffix should resolve to street_address, not person_name
  street_txt <- "Resides at 450 Oak Dr. near downtown."
  d_st <- pii_detect(street_txt)
  expect_equal(nrow(d_st), 1L)
  expect_equal(d_st$entity_type, "street_address")

  # Clinical/academic phrases should NOT falsely trigger unlabeled person_name
  clinical_txt <- paste(
    "Major Depressive Disorder assessed via Cognitive Behavioral Therapy.",
    "Emergency Room intake on Monday Morning in United States."
  )
  d_clin <- pii_detect(clinical_txt)
  expect_equal(nrow(d_clin), 0L)

  # Custom regex, custom dictionary, and allowlist
  cfg <- pii_config(
    custom_patterns = c(study_code = "STUDY-[0-9]{5}"),
    custom_dictionary = list(clinic_name = c("Hartford Behavioral Center")),
    allowlist = c("Dr. Pepper", "Beck Depression Inventory")
  )
  txt <- "At Hartford Behavioral Center (STUDY-10492), client drank Dr. Pepper after Beck Depression Inventory."
  red <- pii_redact(txt, config = cfg)
  expect_match(red, "\\[REDACTED_CLINIC_NAME\\]")
  expect_match(red, "\\[REDACTED_STUDY_CODE\\]")
  expect_match(red, "Dr\\. Pepper")
  expect_match(red, "Beck Depression Inventory")

  # NA and empty string preservation + include_values = FALSE masking
  edge <- c(NA_character_, "", "Email a@b.co")
  expect_equal(is.na(pii_redact(edge)), c(TRUE, FALSE, FALSE))
  expect_equal(pii_redact(edge)[2L], "")
  det_masked <- pii_detect(edge, include_values = FALSE)
  expect_equal(det_masked$match, "[MASKED]")
  expect_equal(det_masked$doc_id, 3L)
})

test_that("pii_pseudonymize and pii_reidentify are deterministic, keyed, and lossless", {
  key1 <- pii_vault_key()
  key2 <- pii_vault_key()
  docs <- c(
    "Session 1: Dr. Jane Doe emailed jane@clinic.org on 2026-01-10.",
    "Session 2: Dr. Jane Doe reported improved sleep; phone (555) 890-1234.",
    NA_character_
  )

  p1 <- pii_pseudonymize(docs, key = key1)
  expect_s3_class(p1, "airgap_pseudonymized")
  expect_s3_class(p1$vault, "airgap_pii_vault")
  expect_s3_class(p1$report, "airgap_privacy_report")
  expect_true(is.na(p1$text[3L]))

  # Raw PII absent from pseudonymized text
  expect_false(grepl("Jane Doe", paste(p1$text, collapse = " "), fixed = TRUE))
  expect_false(grepl("jane@clinic.org", paste(p1$text, collapse = " "), fixed = TRUE))

  # Deterministic coreference: Dr. Jane Doe receives identical token in doc 1 & doc 2
  tok1 <- regmatches(p1$text[1L], regexpr("<<PERSON_NAME_[0-9a-f]{10}>>", p1$text[1L]))
  tok2 <- regmatches(p1$text[2L], regexpr("<<PERSON_NAME_[0-9a-f]{10}>>", p1$text[2L]))
  expect_identical(tok1, tok2)

  # Different key yields different token
  p2 <- pii_pseudonymize(docs, key = key2)
  tok_other <- regmatches(p2$text[1L], regexpr("<<PERSON_NAME_[0-9a-f]{10}>>", p2$text[1L]))
  expect_false(identical(tok1, tok_other))

  # Lossless roundtrip re-identification (vector & data frame)
  expect_identical(pii_reidentify(p1$text, p1$vault), docs)
  df_p <- tibble::tibble(id = 1:3, text = p1$text)
  df_re <- pii_reidentify(df_p, p1$vault, cols = "text")
  expect_identical(df_re$text, docs)

  # Incremental vault reuse with same key works; wrong key fails
  p_batch2 <- pii_pseudonymize("Follow-up with bob@clinic.org", key = key1, vault = p1$vault)
  expect_gt(length(p_batch2$vault$mappings), length(p1$vault$mappings))
  expect_error(
    pii_pseudonymize("Follow-up", key = key2, vault = p1$vault),
    class = "airgap_key_error"
  )

  # print(vault) NEVER prints raw PII values
  vault_print <- paste(capture.output(print(p1$vault)), collapse = "\n")
  expect_false(grepl("Jane Doe", vault_print, fixed = TRUE))
  expect_false(grepl("jane@clinic.org", vault_print, fixed = TRUE))
  expect_false(grepl("890-1234", vault_print, fixed = TRUE))
})

test_that("encrypted PII vault protects secrets at rest and rejects wrong keys or tampering", {
  key <- pii_vault_key()
  wrong_key <- pii_vault_key()
  vault_file <- withr::local_tempfile(fileext = ".vault.json")

  orig <- "Patient: Elena Vance (SSN 123-45-6789, elena.vance@med.org)"
  res <- pii_pseudonymize(orig, key = key, vault_path = vault_file, encrypt_vault = TRUE)
  expect_true(file.exists(vault_file))

  # Disk contents must be encrypted and must NOT contain any plaintext PII
  disk_txt <- paste(readLines(vault_file, warn = FALSE), collapse = "\n")
  expect_false(grepl("Elena Vance", disk_txt, fixed = TRUE))
  expect_false(grepl("123-45-6789", disk_txt, fixed = TRUE))
  expect_false(grepl("elena.vance@med.org", disk_txt, fixed = TRUE))

  # Load and reidentify directly from vault_file path with correct key
  expect_identical(pii_reidentify(res$text, vault = vault_file, key = key), orig)

  # Missing or wrong key fails
  expect_error(pii_vault_load(vault_file, key = NULL), class = "airgap_key_error")
  expect_error(pii_vault_load(vault_file, key = wrong_key), class = "airgap_vault_error")

  # Tampering ciphertext fails HMAC-SHA256 authentication before decryption
  env <- jsonlite::fromJSON(vault_file, simplifyVector = FALSE)
  ct_raw <- openssl::base64_decode(env$ciphertext_b64)
  ct_raw[1L] <- xor(ct_raw[1L], as.raw(0xFF))
  env$ciphertext_b64 <- openssl::base64_encode(ct_raw)
  writeLines(jsonlite::toJSON(env, auto_unbox = TRUE), vault_file)
  expect_error(pii_vault_load(vault_file, key = key), class = "airgap_vault_error")
})

test_that("pii_privacy_report summarizes coverage without leaking any raw sensitive text", {
  df <- tibble::tibble(
    id = 1:3,
    note = c(
      "Dr. Alice Mercer emailed alice.mercer@secret.org on 2026-02-14.",
      "SSN 123-45-6789 verified.",
      "Completely anonymous progress note."
    )
  )
  rep <- pii_privacy_report(df, text_col = "note")
  expect_s3_class(rep, "airgap_privacy_report")
  expect_equal(rep$n_documents, 3L)
  expect_equal(rep$n_documents_with_pii, 2L)
  expect_equal(rep$total_entities, 4L)

  rep_dump <- paste(
    c(capture.output(print(rep)), jsonlite::toJSON(unclass(rep), auto_unbox = TRUE)),
    collapse = "\n"
  )
  for (secret in c("Alice Mercer", "alice.mercer@secret.org", "123-45-6789", "2026-02-14")) {
    expect_false(grepl(secret, rep_dump, fixed = TRUE), info = paste("Report leaked:", secret))
  }
})
