# Pillar 4a: Immutable Hash-Chained IRB/HIPAA JSONL Audit Trail

#' Forbidden raw-text / sensitive keys strictly barred from audit logs
#' @noRd
audit_forbidden_keys <- function() {
  c(
    "text", "raw_text", "input", "inputs", "input_text", "prompt", "prompts",
    "raw_prompt", "response", "responses", "output", "outputs", "raw_output",
    "content", "note", "notes", "narrative", "transcript", "vault", "mappings",
    "pii_values", "matches", "raw_match", "patient_name", "subject_name",
    "student_name", "email", "ssn", "phone", "dob", "address", "mrn"
  )
}

#' Strict allowlist of top-level keys permitted in v1.0 audit log entries
#' @noRd
audit_allowed_fields <- function() {
  c(
    "schema_version",
    "seq",
    "timestamp",
    "event_type",
    "run_id",
    "package_version",
    "r_version",
    "os_info",
    "container_spec_digest",
    "container_backend",
    "container_image_digest",
    "network_mode",
    "model_name",
    "model_digest",
    "endpoint_class",
    "isolation_status",
    "preflight_hash",
    "prompt_template_hash",
    "schema_digest",
    "decoding_params",
    "pii_policy",
    "pii_config_digest",
    "pii_counts",
    "output_pii_leaks",
    "row_counts",
    "metadata",
    "prev_hash",
    "entry_hash"
  )
}

#' Recursively verify no forbidden raw-text keys exist anywhere inside an audit payload
#' @noRd
find_forbidden_audit_keys <- function(x, path = "") {
  if (!is.list(x)) return(character())
  nms <- names(x)
  found <- character()
  forb <- audit_forbidden_keys()

  if (!is.null(nms)) {
    for (i in seq_along(x)) {
      nm <- nms[i]
      key_path <- if (nzchar(path)) paste0(path, ".", nm) else nm
      if (tolower(nm) %in% forb) {
        found <- c(found, key_path)
      }
      # pii_counts keys are entity class labels (e.g., "email", "ssn") with strictly integer values
      if (identical(nm, "pii_counts") && !nzchar(path)) {
        next
      }
      if (is.list(x[[i]])) {
        found <- c(found, find_forbidden_audit_keys(x[[i]], key_path))
      }
    }
  } else {
    for (i in seq_along(x)) {
      if (is.list(x[[i]])) {
        found <- c(found, find_forbidden_audit_keys(x[[i]], paste0(path, "[", i, "]")))
      }
    }
  }
  found
}

#' Recursively scan free-text metadata strings for accidental PII or oversized text blobs
#' @noRd
scan_metadata_for_pii <- function(x, path = "metadata") {
  if (is.null(x)) return(character())
  issues <- character()
  cfg <- pii_config(detect_unlabeled_names = TRUE)

  walk <- function(obj, p) {
    if (is.character(obj)) {
      for (s in obj) {
        if (is.na(s) || !nzchar(s)) next
        if (nchar(s, type = "chars") > 256L) {
          issues <<- c(issues, paste0(p, ": string exceeds 256-character audit metadata limit (possible raw text blob)."))
          next
        }
        det <- pii_detect(s, config = cfg, include_values = FALSE)
        if (nrow(det) > 0L) {
          types <- paste(unique(det$entity_type), collapse = ", ")
          issues <<- c(issues, paste0(p, ": potential PII detected (", types, "); audit logs must remain PII-free."))
        }
      }
    } else if (is.list(obj)) {
      nms <- names(obj)
      for (i in seq_along(obj)) {
        sub_p <- if (!is.null(nms) && nzchar(nms[i])) paste0(p, ".", nms[i]) else paste0(p, "[", i, "]")
        walk(obj[[i]], sub_p)
      }
    }
  }
  walk(x, path)
  issues
}

#' Normalize and strictly validate an audit payload before writing to ledger
#' @noRd
normalize_audit_entry <- function(entry, event_type = "extraction_run", metadata = NULL) {
  if (inherits(entry, c("airgap_extraction", "airgap_consensus"))) {
    entry <- extraction_manifest(entry)
  } else if (inherits(entry, "airgap_preflight")) {
    entry <- list(
      run_id = generate_run_id("preflight"),
      timestamp = entry$checked_at,
      container_spec_digest = entry$spec_digest,
      model_digest = entry$model_digest,
      endpoint_class = entry$endpoint_class,
      isolation_status = entry$status,
      preflight_hash = entry$record_hash
    )
    if (identical(event_type, "extraction_run")) event_type <- "preflight_check"
  } else if (inherits(entry, "airgap_digest_verification")) {
    entry <- list(
      run_id = generate_run_id("digest"),
      timestamp = entry$verified_at,
      model_digest = entry$actual_digest,
      isolation_status = if (isTRUE(entry$matched)) "PASS" else if (isFALSE(entry$matched)) "FAIL" else "COMPUTED"
    )
    if (identical(event_type, "extraction_run")) event_type <- "model_verification"
  }

  if (!is.list(entry) || is.data.frame(entry)) {
    cli::cli_abort(
      "{.arg entry} must be an `airgap_extraction`, `airgap_run_manifest`, `airgap_preflight`, or named list.",
      class = "airgap_validation_error"
    )
  }

  # 1. Reject forbidden raw-text / PII keys anywhere in entry or metadata
  forb_found <- c(
    find_forbidden_audit_keys(entry),
    if (!is.null(metadata)) find_forbidden_audit_keys(metadata, "metadata") else character()
  )
  if (length(forb_found) > 0L) {
    cli::cli_abort(
      c(
        "Audit log privacy violation: raw text or sensitive keys are strictly prohibited in audit logs.",
        "x" = "Forbidden key(s): {paste(unique(forb_found), collapse = ', ')}"
      ),
      class = "airgap_audit_privacy_error"
    )
  }

  # 2. Reject any undeclared top-level keys outside strict audit schema
  allowed <- setdiff(audit_allowed_fields(), c("seq", "prev_hash", "entry_hash"))
  extra_top <- setdiff(names(entry), allowed)
  if (length(extra_top) > 0L) {
    cli::cli_abort(
      c(
        "Audit log schema violation: undeclared top-level field(s) rejected to prevent raw-data leakage.",
        "x" = "Disallowed field(s): {paste(extra_top, collapse = ', ')}",
        "i" = "Place non-sensitive study identifiers in {.arg metadata}."
      ),
      class = "airgap_audit_privacy_error"
    )
  }

  # 3. Validate pii_counts contains strictly non-negative integer counts (never strings/values)
  pii_counts <- entry$pii_counts %||% list()
  if (!is.list(pii_counts)) {
    cli::cli_abort("{.field pii_counts} must be a named list of non-negative integers.", class = "airgap_audit_privacy_error")
  }
  if (length(pii_counts) > 0L) {
    if (is.null(names(pii_counts)) || any(!nzchar(names(pii_counts)))) {
      cli::cli_abort("{.field pii_counts} must have non-empty entity type names.", class = "airgap_audit_privacy_error")
    }
    for (nm in names(pii_counts)) {
      v <- pii_counts[[nm]]
      if (!is.numeric(v) || is.logical(v) || length(v) != 1L || is.na(v) || v < 0 || v != floor(v)) {
        cli::cli_abort(
          "Audit privacy violation: `pii_counts[['{nm}']]` must be a non-negative integer count.",
          class = "airgap_audit_privacy_error"
        )
      }
      pii_counts[[nm]] <- as.integer(v)
    }
  }

  # Validate output_pii_leaks if provided
  out_leaks <- entry$output_pii_leaks
  if (!is.null(out_leaks)) {
    if (!is.numeric(out_leaks) || is.logical(out_leaks) || length(out_leaks) != 1L ||
        is.na(out_leaks) || out_leaks < 0 || out_leaks != floor(out_leaks)) {
      cli::cli_abort("Audit privacy violation: `output_pii_leaks` must be a non-negative integer.", class = "airgap_audit_privacy_error")
    }
    out_leaks <- as.integer(out_leaks)
  }

  # 4. Scan metadata & scalar identifiers for accidental PII
  eff_meta <- metadata %||% entry$metadata
  if (!is.null(eff_meta)) {
    if (!is.list(eff_meta)) {
      cli::cli_abort("{.arg metadata} must be a named list or `NULL`.", class = "airgap_validation_error")
    }
    pii_issues <- scan_metadata_for_pii(eff_meta, "metadata")
    if (length(pii_issues) > 0L) {
      cli::cli_abort(
        c(
          "Audit log privacy violation: potential PII or raw text detected in audit metadata.",
          stats::setNames(pii_issues, rep("x", length(pii_issues)))
        ),
        class = "airgap_audit_privacy_error"
      )
    }
  }

  # Also verify core string identifiers do not contain obvious PII (emails/SSNs/phones)
  id_cfg <- pii_config(entities = c("email", "ssn", "phone", "street_address"), detect_unlabeled_names = FALSE)
  for (fld in c("run_id", "event_type", "model_name")) {
    val <- entry[[fld]]
    if (!is.null(val) && is.character(val) && length(val) == 1L && nzchar(val)) {
      det <- pii_detect(val, config = id_cfg, include_values = FALSE)
      if (nrow(det) > 0L) {
        cli::cli_abort(
          "Audit log privacy violation: field {.field {fld}} contains direct PII ({paste(unique(det$entity_type), collapse = ', ')}).",
          class = "airgap_audit_privacy_error"
        )
      }
    }
  }

  list(
    schema_version = "1.0",
    timestamp = entry$timestamp %||% utc_timestamp(),
    event_type = as.character(entry$event_type %||% event_type)[1L],
    run_id = as.character(entry$run_id %||% generate_run_id("audit"))[1L],
    package_version = as.character(entry$package_version %||% airgapllm_version())[1L],
    r_version = as.character(entry$r_version %||% as.character(getRversion()))[1L],
    os_info = as.character(entry$os_info %||% runtime_os_info())[1L],
    container_spec_digest = entry$container_spec_digest,
    container_backend = entry$container_backend,
    container_image_digest = entry$container_image_digest,
    network_mode = entry$network_mode,
    model_name = entry$model_name,
    model_digest = entry$model_digest,
    endpoint_class = entry$endpoint_class,
    isolation_status = entry$isolation_status,
    preflight_hash = entry$preflight_hash,
    prompt_template_hash = entry$prompt_template_hash,
    schema_digest = entry$schema_digest,
    decoding_params = entry$decoding_params,
    pii_policy = entry$pii_policy,
    pii_config_digest = entry$pii_config_digest,
    pii_counts = pii_counts,
    output_pii_leaks = out_leaks,
    row_counts = entry$row_counts,
    metadata = eff_meta
  )
}

#' Append a Tamper-Evident Entry to an Immutable JSONL Audit Log
#'
#' Writes a cryptographically hash-chained audit record (`prev_hash ->
#' entry_hash`) to a JSONL audit log file. Enforces strict zero-PII-leakage
#' invariants by rejecting raw text keys, undeclared top-level fields,
#' non-integer PII summaries, and any metadata strings containing detectable
#' PII.
#'
#' @param path Character scalar path to the JSONL audit log file.
#' @param entry An `airgap_extraction` result, `airgap_run_manifest`,
#'   `airgap_preflight`, `airgap_digest_verification`, or validated named list
#'   matching the v1.0 audit schema.
#' @param event_type Character scalar event label (default
#'   `"extraction_run"`).
#' @param metadata Optional named list of non-sensitive study metadata (e.g.,
#'   `list(irb_protocol = "IRB-2026-0412", site = "Site-A")`). Scanned for PII
#'   and length-capped at 256 characters per string.
#' @param verify_existing Logical scalar; if `TRUE` (default) and `path`
#'   already exists, verifies the existing hash chain via [audit_log_verify()]
#'   before appending.
#'
#' @return An S3 object of class `"airgap_audit_entry"` representing the
#'   appended record (including `seq`, `prev_hash`, and `entry_hash`).
#'
#' @export
#' @examples
#' tmp_log <- tempfile(fileext = ".jsonl")
#' df <- tibble::tibble(id = "R1", text = "Patient John Doe emailed john@clinic.org.")
#' sc <- extraction_schema(flag = schema_field("logical"))
#' res <- airgap_extract(df, "text", sc, runtime_mock(), id_col = "id")
#' entry <- audit_log_append(tmp_log, res)
#' audit_log_verify(tmp_log)
#' unlink(tmp_log)
audit_log_append <- function(
  path,
  entry,
  event_type = "extraction_run",
  metadata = NULL,
  verify_existing = TRUE
) {
  assert_scalar_string(path, "path")
  assert_scalar_string(event_type, "event_type")
  assert_scalar_logical(verify_existing, "verify_existing")

  norm <- normalize_audit_entry(entry, event_type = event_type, metadata = metadata)

  prev_seq <- 0L
  prev_hash <- "GENESIS"

  if (file.exists(path) && file.info(path)$size > 0) {
    if (isTRUE(verify_existing)) {
      ver <- audit_log_verify(path, strict = TRUE)
      if (!isTRUE(ver$valid)) {
        cli::cli_abort(
          c(
            "Refusing to append to tampered or corrupted audit log {.path {path}}.",
            stats::setNames(ver$issues, rep("x", length(ver$issues)))
          ),
          class = "airgap_audit_tamper_error"
        )
      }
      prev_seq <- ver$n_entries
      prev_hash <- ver$chain_head_hash
    } else {
      lines <- readLines(path, warn = FALSE, encoding = "UTF-8")
      lines <- lines[nzchar(trimws(lines))]
      if (length(lines) > 0L) {
        last_rec <- jsonlite::fromJSON(lines[length(lines)], simplifyVector = FALSE)
        if (is.null(last_rec$seq) || is.null(last_rec$entry_hash)) {
          cli::cli_abort("Malformed tail entry in audit log {.path {path}}.", class = "airgap_audit_tamper_error")
        }
        prev_seq <- as.integer(last_rec$seq)
        prev_hash <- as.character(last_rec$entry_hash)
      }
    }
  }

  record_body <- c(
    list(seq = as.integer(prev_seq + 1L)),
    norm,
    list(prev_hash = prev_hash)
  )
  entry_hash <- sha256_object(record_body)
  full_record <- c(record_body, list(entry_hash = entry_hash))

  jsonl_append_line(path, full_record)
  structure(full_record, class = "airgap_audit_entry")
}

#' @export
print.airgap_audit_entry <- function(x, ...) {
  cat("<airgap_audit_entry> #", x$seq, " [", x$event_type, "]\n", sep = "")
  cat("  Run ID:       ", x$run_id, "\n", sep = "")
  cat("  Timestamp:    ", x$timestamp, "\n", sep = "")
  cat("  Isolation:    ", x$isolation_status %||% "NA", "\n", sep = "")
  cat("  PII policy:   ", x$pii_policy %||% "NA", "\n", sep = "")
  cat("  Prev hash:    ", substr(x$prev_hash, 1L, 24L), "\n", sep = "")
  cat("  Entry hash:   ", x$entry_hash, "\n", sep = "")
  invisible(x)
}

#' Read Entries from an Immutable JSONL Audit Log
#'
#' Parses all entries in an `airgapllm` JSONL audit log into a structured list
#' with a companion summary `tibble`.
#'
#' @param path Character scalar path to the JSONL audit log file.
#'
#' @return An S3 object of class `"airgap_audit_log"` containing `path`,
#'   `entries` (list of parsed records), and `summary` (tibble).
#'
#' @export
#' @examples
#' tmp_log <- tempfile(fileext = ".jsonl")
#' pf <- preflight_isolation_check(endpoint = "http://127.0.0.1:11434")
#' audit_log_append(tmp_log, pf)
#' audit_log_read(tmp_log)
#' unlink(tmp_log)
audit_log_read <- function(path) {
  assert_scalar_string(path, "path")
  if (!file.exists(path)) {
    cli::cli_abort("Audit log file does not exist: {.path {path}}.", class = "airgap_audit_error")
  }
  lines <- readLines(path, warn = FALSE, encoding = "UTF-8")
  lines <- lines[nzchar(trimws(lines))]
  entries <- lapply(seq_along(lines), function(i) {
    tryCatch(
      jsonlite::fromJSON(lines[i], simplifyVector = FALSE),
      error = function(e) {
        cli::cli_abort("Malformed JSON on audit log line {i}: {conditionMessage(e)}", class = "airgap_audit_error")
      }
    )
  })

  if (length(entries) == 0L) {
    summ <- tibble::tibble(
      seq = integer(),
      timestamp = character(),
      event_type = character(),
      run_id = character(),
      model_name = character(),
      isolation_status = character(),
      pii_policy = character(),
      entry_hash = character()
    )
  } else {
    summ <- tibble::tibble(
      seq = vapply(entries, function(e) as.integer(e$seq %||% NA_integer_), integer(1L)),
      timestamp = vapply(entries, function(e) as.character(e$timestamp %||% NA_character_), character(1L)),
      event_type = vapply(entries, function(e) as.character(e$event_type %||% NA_character_), character(1L)),
      run_id = vapply(entries, function(e) as.character(e$run_id %||% NA_character_), character(1L)),
      model_name = vapply(entries, function(e) as.character(e$model_name %||% NA_character_), character(1L)),
      isolation_status = vapply(entries, function(e) as.character(e$isolation_status %||% NA_character_), character(1L)),
      pii_policy = vapply(entries, function(e) as.character(e$pii_policy %||% NA_character_), character(1L)),
      entry_hash = vapply(entries, function(e) as.character(e$entry_hash %||% NA_character_), character(1L))
    )
  }

  structure(
    list(path = normalizePath(path, winslash = "/", mustWork = TRUE), entries = entries, summary = summ),
    class = "airgap_audit_log"
  )
}

#' @export
print.airgap_audit_log <- function(x, ...) {
  cat("<airgap_audit_log> (", length(x$entries), " entries)\n", sep = "")
  cat("  Path: ", x$path, "\n", sep = "")
  if (nrow(x$summary) > 0L) {
    print(x$summary)
  }
  invisible(x)
}

#' Verify Cryptographic Integrity and Zero-PII Invariants of an Audit Log
#'
#' Recomputes the SHA-256 hash chain from `GENESIS` through the final entry in
#' a JSONL audit log, verifying sequence continuity (`1..n`), `prev_hash` links,
#' exact `entry_hash` digests, and absence of forbidden raw-text keys. Detects
#' field edits, deletions, insertions, line reordering, and truncation.
#'
#' @param path Character scalar path to the JSONL audit log file.
#' @param strict Logical scalar; if `TRUE` (default), also verifies that all
#'   top-level fields belong to the strict v1.0 audit schema allowlist.
#'
#' @return An S3 object of class `"airgap_audit_verification"` with elements
#'   `valid`, `n_entries`, `first_invalid_seq`, `chain_head_hash`, `issues`,
#'   and `verified_at`.
#'
#' @export
#' @examples
#' tmp_log <- tempfile(fileext = ".jsonl")
#' pf <- preflight_isolation_check(endpoint = "http://127.0.0.1:11434")
#' audit_log_append(tmp_log, pf)
#' audit_log_verify(tmp_log)
#' unlink(tmp_log)
audit_log_verify <- function(path, strict = TRUE) {
  assert_scalar_string(path, "path")
  assert_scalar_logical(strict, "strict")

  if (!file.exists(path)) {
    return(structure(
      list(
        valid = FALSE,
        n_entries = 0L,
        first_invalid_seq = 1L,
        chain_head_hash = NULL,
        issues = paste0("Audit log file does not exist: ", path),
        verified_at = utc_timestamp()
      ),
      class = "airgap_audit_verification"
    ))
  }

  raw_recs <- read_jsonl_raw_lines(path)
  n <- length(raw_recs)

  if (n == 0L) {
    return(structure(
      list(
        valid = FALSE,
        n_entries = 0L,
        first_invalid_seq = 1L,
        chain_head_hash = NULL,
        issues = "Audit log file is empty.",
        verified_at = utc_timestamp()
      ),
      class = "airgap_audit_verification"
    ))
  }

  issues <- character()
  first_bad <- NA_integer_
  expected_prev <- "GENESIS"
  head_hash <- NULL
  allowed_all <- audit_allowed_fields()

  mark_bad <- function(line_idx, msg) {
    issues <<- c(issues, paste0("Line ", line_idx, ": ", msg))
    if (is.na(first_bad)) first_bad <<- as.integer(line_idx)
  }

  for (i in seq_len(n)) {
    item <- raw_recs[[i]]
    if (isTRUE(item$has_nul) || !isTRUE(item$valid_utf8)) {
      mark_bad(i, "Corrupted UTF-8 or embedded NUL byte detected.")
      next
    }
    rec <- tryCatch(
      jsonlite::fromJSON(item$text, simplifyVector = FALSE),
      error = function(e) NULL
    )
    if (is.null(rec) || !is.list(rec) || is.null(names(rec))) {
      mark_bad(i, "Malformed JSON object.")
      next
    }

    # Check sequence monotonicity
    if (is.null(rec$seq) || !is.numeric(rec$seq) || as.integer(rec$seq) != i) {
      mark_bad(i, paste0("Sequence mismatch (expected seq=", i, ", found ", rec$seq %||% "NULL", ")."))
    }

    # Check prev_hash linkage in constant time
    if (!constant_time_equal(as.character(rec$prev_hash %||% ""), expected_prev)) {
      mark_bad(i, paste0("Broken chain link: prev_hash does not match expected '", expected_prev, "'."))
    }

    # Check forbidden raw-text keys
    forb <- find_forbidden_audit_keys(rec)
    if (length(forb) > 0L) {
      mark_bad(i, paste0("Forbidden raw-text key(s) present: ", paste(unique(forb), collapse = ", "), "."))
    }

    # Strict schema allowlist check
    if (isTRUE(strict)) {
      extra <- setdiff(names(rec), allowed_all)
      if (length(extra) > 0L) {
        mark_bad(i, paste0("Undeclared field(s) outside audit schema: ", paste(extra, collapse = ", "), "."))
      }
    }

    # Recompute entry_hash and verify in constant time
    stored_hash <- rec$entry_hash
    if (!is_valid_sha256_digest(stored_hash)) {
      mark_bad(i, "Missing or invalid entry_hash.")
      expected_prev <- if (is.character(stored_hash) && length(stored_hash) == 1L) stored_hash else "INVALID"
      next
    }

    body <- rec[setdiff(names(rec), "entry_hash")]
    computed_hash <- sha256_object(body)
    if (!constant_time_equal(computed_hash, stored_hash)) {
      mark_bad(i, paste0("Hash mismatch (tampered entry): stored ", stored_hash, " != computed ", computed_hash, "."))
    }

    expected_prev <- stored_hash
    head_hash <- stored_hash
  }

  structure(
    list(
      valid = length(issues) == 0L,
      n_entries = as.integer(n),
      first_invalid_seq = first_bad,
      chain_head_hash = head_hash,
      issues = issues,
      verified_at = utc_timestamp()
    ),
    class = "airgap_audit_verification"
  )
}

#' @export
print.airgap_audit_verification <- function(x, ...) {
  status <- if (isTRUE(x$valid)) "VALID" else "TAMPERED / INVALID"
  cat("<airgap_audit_verification> [", status, "]\n", sep = "")
  cat("  Entries verified: ", x$n_entries, "\n", sep = "")
  if (!is.null(x$chain_head_hash)) {
    cat("  Chain head hash:  ", x$chain_head_hash, "\n", sep = "")
  }
  if (!isTRUE(x$valid)) {
    cat("  First invalid:    line ", x$first_invalid_seq, "\n", sep = "")
    for (iss in x$issues) {
      cat("  [!] ", iss, "\n", sep = "")
    }
  }
  invisible(x)
}
