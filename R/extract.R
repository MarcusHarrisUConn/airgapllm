# Pillar 3c: Crash-Resumable Schema-Enforced Batch Extractor

#' Default extraction prompt template
#' @noRd
default_prompt_template <- function(schema) {
  schema_json <- as.character(jsonlite::toJSON(as_json_schema(schema), auto_unbox = TRUE, pretty = TRUE))
  paste(
    "Extract structured fields from the following de-identified research text.",
    "Return ONLY a single valid JSON object adhering strictly to this schema:",
    schema_json,
    "",
    "TEXT:",
    "{text}",
    sep = "\n"
  )
}

#' Render prompt template with sanitized text
#' @noRd
render_extraction_prompt <- function(template, sanitized_text) {
  if (!grepl("{text}", template, fixed = TRUE)) {
    return(paste0(template, "\n\n", sanitized_text))
  }
  gsub("{text}", sanitized_text, template, fixed = TRUE)
}

#' Append a single JSON line atomically to a JSONL file
#' @noRd
jsonl_append_line <- function(path, obj) {
  line <- canonical_json(obj)
  dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE)
  con <- file(path, open = "ab")
  on.exit(try(close(con), silent = TRUE), add = TRUE)
  writeBin(charToRaw(paste0(enc2utf8(line), "\n")), con = con)
  flush(con)
  invisible(line)
}

#' Load and validate an existing crash-resumable JSONL checkpoint ledger
#' @noRd
checkpoint_load <- function(path, schema_digest, prompt_template_hash, pii_policy, model) {
  if (!file.exists(path) || file.info(path)$size == 0) {
    return(list(exists = FALSE, rows = list(), recovered_partial = FALSE))
  }

  raw_lines <- readLines(path, warn = FALSE, encoding = "UTF-8")
  raw_lines <- raw_lines[nzchar(trimws(raw_lines))]
  if (length(raw_lines) == 0L) {
    return(list(exists = FALSE, rows = list(), recovered_partial = FALSE))
  }

  header <- tryCatch(
    jsonlite::fromJSON(raw_lines[1L], simplifyVector = FALSE),
    error = function(e) NULL
  )
  if (is.null(header) || !identical(header$record_type, "header")) {
    cli::cli_abort(
      "Checkpoint file {.path {path}} is missing a valid header record.",
      class = "airgap_checkpoint_error"
    )
  }

  if (!identical(header$schema_digest, schema_digest)) {
    cli::cli_abort(
      c(
        "Checkpoint schema mismatch: cannot resume into a different extraction schema.",
        "x" = "Checkpoint schema digest: {header$schema_digest}",
        "x" = "Current schema digest:    {schema_digest}"
      ),
      class = "airgap_checkpoint_error"
    )
  }
  if (!identical(header$prompt_template_hash, prompt_template_hash)) {
    cli::cli_abort(
      "Checkpoint prompt template hash mismatch: start a new checkpoint file for a modified prompt.",
      class = "airgap_checkpoint_error"
    )
  }
  if (!identical(header$pii_policy, pii_policy)) {
    cli::cli_abort(
      "Checkpoint PII policy mismatch (checkpoint: '{header$pii_policy}', current: '{pii_policy}').",
      class = "airgap_checkpoint_error"
    )
  }

  rows <- list()
  valid_lines <- raw_lines[1L]
  recovered_partial <- FALSE

  if (length(raw_lines) > 1L) {
    for (idx in 2:length(raw_lines)) {
      ln <- raw_lines[idx]
      rec <- tryCatch(
        jsonlite::fromJSON(ln, simplifyVector = FALSE),
        error = function(e) NULL
      )
      if (is.null(rec) || !identical(rec$record_type, "row") || is.null(rec$row_id)) {
        if (idx == length(raw_lines)) {
          # Truncated trailing line from a sudden crash: recover cleanly
          recovered_partial <- TRUE
          cli::cli_warn(
            "Recovered from truncated trailing checkpoint line in {.path {path}}; resuming from last committed row."
          )
          break
        }
        cli::cli_abort(
          "Corrupt checkpoint entry at line {idx} of {.path {path}}.",
          class = "airgap_checkpoint_error"
        )
      }
      rows[[as.character(rec$row_id)]] <- rec
      valid_lines <- c(valid_lines, ln)
    }
  }

  # Rewrite clean prefix atomically if trailing line was truncated
  if (isTRUE(recovered_partial)) {
    tmp_path <- paste0(path, ".recover.", Sys.getpid())
    writeLines(valid_lines, con = tmp_path, useBytes = TRUE)
    file.rename(tmp_path, path)
  }

  list(exists = TRUE, rows = rows, recovered_partial = recovered_partial)
}

#' Assemble typed columns from row extraction records
#' @noRd
assemble_extraction_tibble <- function(row_ids, id_col_name, records, schema) {
  n <- length(row_ids)
  cols <- list()
  cols[[id_col_name]] <- row_ids

  for (nm in names(schema$fields)) {
    f <- schema$fields[[nm]]
    na_val <- typed_na_for_field(f)
    vec <- rep(na_val, n)
    for (i in seq_len(n)) {
      rec <- records[[row_ids[i]]]
      if (!is.null(rec) && identical(rec$status, "ok") && !is.null(rec$data)) {
        val <- rec$data[[nm]]
        if (!is.null(val) && !(length(val) == 1L && is.na(val))) {
          vec[i] <- switch(
            f$type,
            "character" = as.character(val),
            "enum" = as.character(val),
            "integer" = as.integer(val),
            "numeric" = as.numeric(val),
            "logical" = as.logical(val)
          )
        }
      }
    }
    cols[[nm]] <- vec
  }

  cols[[".status"]] <- vapply(row_ids, function(rid) {
    rec <- records[[rid]]
    if (is.null(rec)) "failed" else as.character(rec$status)
  }, character(1L), USE.NAMES = FALSE)

  cols[[".attempts"]] <- vapply(row_ids, function(rid) {
    rec <- records[[rid]]
    if (is.null(rec)) 0L else as.integer(rec$attempts)
  }, integer(1L), USE.NAMES = FALSE)

  cols[[".error"]] <- vapply(row_ids, function(rid) {
    rec <- records[[rid]]
    if (is.null(rec) || is.null(rec$error)) NA_character_ else as.character(rec$error)
  }, character(1L), USE.NAMES = FALSE)

  cols[[".elapsed_ms"]] <- vapply(row_ids, function(rid) {
    rec <- records[[rid]]
    if (is.null(rec) || is.null(rec$elapsed_ms)) NA_real_ else as.numeric(rec$elapsed_ms)
  }, numeric(1L), USE.NAMES = FALSE)

  tibble::as_tibble(cols)
}

#' Run Crash-Resumable, Schema-Enforced Batch Extraction Over a Data Frame
#'
#' Processes text rows in an R data frame through a local air-gapped LLM
#' runtime into a strictly typed `tibble` with:
#' 1. Pre-flight air-gap isolation verification ([preflight_isolation_check()]),
#' 2. Mandatory pre-inference PII redaction or keyed HMAC-SHA256
#'    pseudonymization (or explicit `"verified_deidentified"` attestation),
#' 3. Strict JSON schema validation ([validate_extraction()]) with automatic
#'    structured repair retries ([build_repair_prompt()]),
#' 4. Crash-resumable atomic per-row JSONL checkpointing (never storing raw
#'    input text), and
#' 5. Optional automatic hash-chained PII-free IRB/HIPAA audit logging
#'    ([audit_log_append()]).
#'
#' @param data A data frame containing input text rows.
#' @param text_col Character scalar name of the text column in `data`.
#' @param schema An [extraction_schema()] object defining output column types
#'   and constraints.
#' @param runtime A local air-gapped runtime created by [runtime_ollama()],
#'   [runtime_openai_local()], or [runtime_mock()].
#' @param prompt_template Optional character scalar prompt template containing
#'   `"{text}"`. Defaults to a strict JSON schema extraction prompt.
#' @param id_col Optional character scalar column name in `data` supplying
#'   unique non-NA row identifiers. If `NULL`, synthesizes `.row_id` as
#'   `"1"`, `"2"`, ..., `"N"`.
#' @param pii_policy Character scalar pre-inference privacy policy: `"redact"`
#'   (default), `"pseudonymize"`, or `"verified_deidentified"`.
#' @param pii_config Optional [pii_config()] object used when `pii_policy` is
#'   `"redact"` or `"pseudonymize"`. Defaults to `pii_config()`.
#' @param pii_key Secret key (e.g., from [pii_vault_key()]) required when
#'   `pii_policy = "pseudonymize"`.
#' @param vault Optional existing `airgap_pii_vault` to accumulate mappings
#'   when `pii_policy = "pseudonymize"`.
#' @param vault_path Optional path to persist the separate encrypted PII vault
#'   when `pii_policy = "pseudonymize"`.
#' @param encrypt_vault Logical scalar; encrypt saved vault file. Defaults to
#'   `TRUE`.
#' @param reidentify_output Logical scalar; if `TRUE` and
#'   `pii_policy = "pseudonymize"`, locally re-identifies character output
#'   columns using the vault after inference. Defaults to `FALSE`.
#' @param checkpoint_path Optional path to an atomic JSONL checkpoint file
#'   enabling crash-resumable execution across interruptions.
#' @param resume Logical scalar; if `TRUE` (default) and `checkpoint_path`
#'   exists, skips rows already committed in the checkpoint. If `FALSE`, starts
#'   a fresh checkpoint file (overwriting any existing file at
#'   `checkpoint_path`).
#' @param retry_failed Logical scalar; when resuming from a checkpoint, whether
#'   to re-attempt rows previously recorded with `.status == "failed"`.
#'   Defaults to `FALSE`.
#' @param max_retries Non-negative integer maximum structured repair retries
#'   after an initial invalid generation. Defaults to `2L`.
#' @param container_spec Optional [airgap_container_spec()] verified in
#'   pre-flight and recorded in the run manifest/audit trail. Defaults to
#'   `runtime$container_spec`.
#' @param model_path Optional path to local model weights verified against
#'   `container_spec$model_digest` or `runtime$model_digest` during pre-flight.
#' @param allow_internal_network Logical scalar passed to
#'   [preflight_isolation_check()]. Defaults to `FALSE`.
#' @param audit_log_path Optional path to an immutable hash-chained JSONL audit
#'   log appended via [audit_log_append()].
#' @param run_id Optional character scalar run identifier. Defaults to an
#'   auto-generated UTC run ID.
#' @param progress Logical scalar; emit brief CLI progress summary. Defaults to
#'   `FALSE`.
#'
#' @return A `tibble` of class `c("airgap_extraction", "tbl_df", "tbl",
#'   "data.frame")` containing the row ID column, strictly typed schema
#'   columns, and per-row metadata (`.status`, `.attempts`, `.error`,
#'   `.elapsed_ms`). Attachable provenance objects are accessed via
#'   [extraction_manifest()], [extraction_privacy_report()],
#'   [extraction_preflight()], [extraction_vault()], and
#'   [extraction_throughput()].
#'
#' @export
#' @examples
#' df <- tibble::tibble(
#'   note_id = c("N1", "N2"),
#'   note_text = c(
#'     "Dr. Jane Doe (MRN: 102938) reports mild anxiety, sleep improved.",
#'     "Email bob@example.org for scheduling; mood stable."
#'   )
#' )
#' sc <- extraction_schema(
#'   severity = schema_field("enum", values = c("mild", "moderate", "severe")),
#'   score = schema_field("integer", min = 0L, max = 10L)
#' )
#' res <- airgap_extract(df, "note_text", sc, runtime_mock(), id_col = "note_id")
#' res
airgap_extract <- function(
  data,
  text_col,
  schema,
  runtime,
  prompt_template = NULL,
  id_col = NULL,
  pii_policy = c("redact", "pseudonymize", "verified_deidentified"),
  pii_config = NULL,
  pii_key = NULL,
  vault = NULL,
  vault_path = NULL,
  encrypt_vault = TRUE,
  reidentify_output = FALSE,
  checkpoint_path = NULL,
  resume = TRUE,
  retry_failed = FALSE,
  max_retries = 2L,
  container_spec = NULL,
  model_path = NULL,
  allow_internal_network = FALSE,
  audit_log_path = NULL,
  run_id = NULL,
  progress = FALSE
) {
  if (!is.data.frame(data)) {
    cli::cli_abort("{.arg data} must be a data frame or tibble.", class = "airgap_validation_error")
  }
  assert_scalar_string(text_col, "text_col")
  if (!text_col %in% names(data)) {
    cli::cli_abort("Column {.val {text_col}} not found in {.arg data}.", class = "airgap_validation_error")
  }
  if (!inherits(schema, "airgap_schema")) {
    cli::cli_abort("{.arg schema} must be an `airgap_schema` object.", class = "airgap_validation_error")
  }
  if (!inherits(runtime, "airgap_runtime")) {
    cli::cli_abort("{.arg runtime} must be an `airgap_runtime` object.", class = "airgap_validation_error")
  }
  pii_policy <- match.arg(pii_policy)
  if (is.null(pii_config)) {
    pii_config <- pii_config()
  }
  if (!inherits(pii_config, "airgap_pii_config")) {
    cli::cli_abort("{.arg pii_config} must be an `airgap_pii_config` object.", class = "airgap_validation_error")
  }
  if (!is.numeric(max_retries) || length(max_retries) != 1L || is.na(max_retries) ||
      max_retries < 0 || max_retries != floor(max_retries)) {
    cli::cli_abort("{.arg max_retries} must be a non-negative integer.", class = "airgap_validation_error")
  }
  max_retries <- as.integer(max_retries)
  assert_scalar_logical(resume, "resume")
  assert_scalar_logical(retry_failed, "retry_failed")
  assert_scalar_logical(reidentify_output, "reidentify_output")
  assert_scalar_logical(encrypt_vault, "encrypt_vault")
  assert_scalar_logical(allow_internal_network, "allow_internal_network")
  assert_scalar_logical(progress, "progress")

  if (is.null(id_col)) {
    id_col_name <- ".row_id"
    row_ids <- as.character(seq_len(nrow(data)))
  } else {
    assert_scalar_string(id_col, "id_col")
    if (!id_col %in% names(data)) {
      cli::cli_abort("ID column {.val {id_col}} not found in {.arg data}.", class = "airgap_validation_error")
    }
    id_col_name <- id_col
    row_ids <- as.character(data[[id_col]])
    if (any(is.na(row_ids)) || any(!nzchar(row_ids))) {
      cli::cli_abort("{.arg id_col} values must be non-NA and non-empty.", class = "airgap_validation_error")
    }
    if (anyDuplicated(row_ids)) {
      cli::cli_abort("{.arg id_col} values must be unique for deterministic checkpointing.", class = "airgap_validation_error")
    }
  }

  # 1. Pre-flight isolation check BEFORE touching any sensitive text
  eff_spec <- container_spec %||% runtime$container_spec
  eff_model_digest <- (if (!is.null(eff_spec)) eff_spec$model_digest else NULL) %||% runtime$model_digest
  preflight <- preflight_isolation_check(
    spec = eff_spec,
    endpoint = runtime,
    model_path = model_path,
    expected_model_digest = eff_model_digest,
    allow_internal_network = allow_internal_network,
    error_on_fail = TRUE
  )

  # 2. Prompt template setup & hash
  template <- prompt_template %||% default_prompt_template(schema)
  assert_scalar_string(template, "prompt_template")
  prompt_template_hash <- sha256_string(template)
  run_id <- run_id %||% generate_run_id("run")

  # 3. Mandatory Pre-Inference Privacy & PII Gate
  raw_texts <- as.character(data[[text_col]])
  active_vault <- NULL

  if (identical(pii_policy, "redact")) {
    red <- pii_redact(raw_texts, config = pii_config, return_details = TRUE)
    sanitized_texts <- red$text
    privacy_report <- red$report
  } else if (identical(pii_policy, "pseudonymize")) {
    if (is.null(pii_key)) {
      cli::cli_abort(
        c(
          "{.arg pii_key} is required when `pii_policy = 'pseudonymize'`.",
          "i" = "Generate a strong key with `pii_vault_key()`."
        ),
        class = "airgap_key_error"
      )
    }
    pse <- pii_pseudonymize(
      raw_texts,
      key = pii_key,
      config = pii_config,
      vault = vault,
      vault_path = vault_path,
      encrypt_vault = encrypt_vault
    )
    sanitized_texts <- pse$text
    privacy_report <- pse$report
    active_vault <- pse$vault
  } else {
    # Explicit "verified_deidentified" attestation
    sanitized_texts <- raw_texts
    privacy_report <- structure(
      list(
        n_documents = as.integer(length(raw_texts)),
        n_documents_with_pii = 0L,
        pct_documents_with_pii = 0,
        total_entities = 0L,
        by_entity = tibble::tibble(
          entity_type = character(),
          count = integer(),
          n_documents = integer(),
          pct_documents = numeric()
        ),
        config_digest = pii_config$config_digest,
        generated_at = utc_timestamp()
      ),
      class = "airgap_privacy_report"
    )
  }

  # 4. Initialize or Resume Atomic JSONL Checkpoint Ledger
  records <- list()
  if (!is.null(checkpoint_path)) {
    assert_scalar_string(checkpoint_path, "checkpoint_path")
    if (isTRUE(resume) && file.exists(checkpoint_path)) {
      ck <- checkpoint_load(
        path = checkpoint_path,
        schema_digest = schema$schema_digest,
        prompt_template_hash = prompt_template_hash,
        pii_policy = pii_policy,
        model = runtime$model
      )
      records <- ck$rows
    } else {
      if (file.exists(checkpoint_path)) {
        unlink(checkpoint_path)
      }
      jsonl_append_line(checkpoint_path, list(
        record_type = "header",
        checkpoint_version = "1.0",
        run_id = run_id,
        schema_digest = schema$schema_digest,
        prompt_template_hash = prompt_template_hash,
        pii_policy = pii_policy,
        model = runtime$model,
        created_at = utc_timestamp()
      ))
    }
  }

  # Determine which rows are already completed in checkpoint
  is_resumed <- vapply(row_ids, function(rid) {
    rec <- records[[rid]]
    if (is.null(rec)) return(FALSE)
    if (identical(rec$status, "ok")) return(TRUE)
    !isTRUE(retry_failed)
  }, logical(1L))

  rows_resumed <- sum(is_resumed)
  rows_processed <- 0L
  total_retries_new <- 0L
  t_start <- proc.time()[["elapsed"]]

  if (isTRUE(progress)) {
    cli::cli_inform(
      "airgap_extract [{run_id}]: {nrow(data)} total rows ({rows_resumed} resumed, {nrow(data) - rows_resumed} pending)."
    )
  }

  # 5. Per-Row Inference + Schema Validation + Structured Repair Retries + Atomic Checkpoint
  for (i in seq_along(row_ids)) {
    if (isTRUE(is_resumed[i])) next
    rid <- row_ids[i]
    row_t0 <- proc.time()[["elapsed"]]
    san_text <- sanitized_texts[i]

    if (is.na(san_text) || !nzchar(trimws(san_text))) {
      rec <- list(
        record_type = "row",
        row_id = rid,
        status = "failed",
        attempts = 0L,
        data = NULL,
        error = "Input text is NA or empty.",
        input_sha256 = sha256_string(""),
        elapsed_ms = round((proc.time()[["elapsed"]] - row_t0) * 1000, 2),
        timestamp = utc_timestamp()
      )
      records[[rid]] <- rec
      if (!is.null(checkpoint_path)) jsonl_append_line(checkpoint_path, rec)
      rows_processed <- rows_processed + 1L
      next
    }

    base_prompt <- render_extraction_prompt(template, san_text)
    current_prompt <- base_prompt
    final_status <- "failed"
    final_data <- NULL
    final_error <- NULL
    attempts_used <- 0L

    for (attempt in seq_len(max_retries + 1L)) {
      attempts_used <- attempt
      raw_out <- runtime_invoke(
        runtime = runtime,
        prompt = current_prompt,
        schema = schema,
        row_id = rid,
        attempt = attempt
      )
      val <- validate_extraction(raw_out, schema)
      if (isTRUE(val$valid)) {
        final_status <- "ok"
        final_data <- val$data
        final_error <- NULL
        break
      }

      final_error <- paste(val$errors, collapse = " ")
      if (attempt <= max_retries) {
        total_retries_new <- total_retries_new + 1L
        current_prompt <- build_repair_prompt(
          original_prompt = base_prompt,
          invalid_output = raw_out,
          errors = val$errors,
          schema = schema
        )
      }
    }

    rec <- list(
      record_type = "row",
      row_id = rid,
      status = final_status,
      attempts = as.integer(attempts_used),
      data = final_data,
      error = final_error,
      input_sha256 = sha256_string(san_text),
      elapsed_ms = round((proc.time()[["elapsed"]] - row_t0) * 1000, 2),
      timestamp = utc_timestamp()
    )
    records[[rid]] <- rec
    if (!is.null(checkpoint_path)) {
      jsonl_append_line(checkpoint_path, rec)
    }
    rows_processed <- rows_processed + 1L
  }

  elapsed_sec <- max(proc.time()[["elapsed"]] - t_start, 1e-6)

  # 6. Assemble strictly typed tibble
  res_tbl <- assemble_extraction_tibble(
    row_ids = row_ids,
    id_col_name = id_col_name,
    records = records,
    schema = schema
  )

  # Optional local re-identification of character schema output columns
  if (isTRUE(reidentify_output) && identical(pii_policy, "pseudonymize") && !is.null(active_vault)) {
    char_schema_cols <- names(schema$fields)[vapply(
      schema$fields,
      function(f) identical(f$type, "character"),
      logical(1L)
    )]
    if (length(char_schema_cols) > 0L) {
      res_tbl <- pii_reidentify(res_tbl, vault = active_vault, cols = char_schema_cols)
    }
  }

  rows_succeeded <- sum(res_tbl$.status == "ok")
  rows_failed <- sum(res_tbl$.status != "ok")
  total_retries_all <- sum(pmax(0L, res_tbl$.attempts - 1L))

  throughput <- list(
    rows_total = as.integer(nrow(data)),
    rows_resumed = as.integer(rows_resumed),
    rows_processed = as.integer(rows_processed),
    rows_succeeded = as.integer(rows_succeeded),
    rows_failed = as.integer(rows_failed),
    total_retries = as.integer(total_retries_all),
    elapsed_sec = round(elapsed_sec, 4),
    rows_per_sec = round(rows_processed / elapsed_sec, 2)
  )

  # Build aggregate PII counts named list (integers only, zero raw values)
  pii_counts <- list()
  if (nrow(privacy_report$by_entity) > 0L) {
    for (k in seq_len(nrow(privacy_report$by_entity))) {
      pii_counts[[privacy_report$by_entity$entity_type[k]]] <- as.integer(privacy_report$by_entity$count[k])
    }
  }

  manifest <- structure(
    list(
      run_id = run_id,
      timestamp = utc_timestamp(),
      package_version = airgapllm_version(),
      r_version = as.character(getRversion()),
      os_info = runtime_os_info(),
      container_spec_digest = if (!is.null(eff_spec)) eff_spec$spec_digest else NULL,
      container_backend = if (!is.null(eff_spec)) eff_spec$backend else runtime$backend_type,
      container_image_digest = if (!is.null(eff_spec)) eff_spec$image_digest else NULL,
      network_mode = if (!is.null(eff_spec)) eff_spec$network_mode else NULL,
      model_name = runtime$model,
      model_digest = preflight$model_digest %||% eff_model_digest,
      endpoint_class = preflight$endpoint_class %||% runtime$endpoint_class,
      isolation_status = preflight$status,
      preflight_hash = preflight$record_hash,
      prompt_template_hash = prompt_template_hash,
      schema_digest = schema$schema_digest,
      decoding_params = runtime$decoding_params,
      pii_policy = pii_policy,
      pii_config_digest = pii_config$config_digest,
      pii_counts = pii_counts,
      row_counts = list(
        total = throughput$rows_total,
        resumed = throughput$rows_resumed,
        processed = throughput$rows_processed,
        succeeded = throughput$rows_succeeded,
        failed = throughput$rows_failed,
        total_retries = throughput$total_retries
      )
    ),
    class = "airgap_run_manifest"
  )

  audit_entry <- NULL
  if (!is.null(audit_log_path)) {
    audit_entry <- audit_log_append(audit_log_path, manifest, event_type = "extraction_run")
  }

  attr(res_tbl, "airgap_manifest") <- manifest
  attr(res_tbl, "airgap_privacy_report") <- privacy_report
  attr(res_tbl, "airgap_preflight") <- preflight
  attr(res_tbl, "airgap_vault") <- active_vault
  attr(res_tbl, "airgap_throughput") <- throughput
  attr(res_tbl, "airgap_audit_entry") <- audit_entry
  class(res_tbl) <- c("airgap_extraction", class(res_tbl))

  res_tbl
}

#' Access Run Provenance and Privacy Metadata from an `airgap_extraction`
#'
#' Convenience accessors for the cryptographic run manifest, aggregate privacy
#' report, pre-flight isolation attestation, separate pseudonymization vault,
#' and throughput metrics attached to an [airgap_extract()] result.
#'
#' @param x An `airgap_extraction` tibble returned by [airgap_extract()].
#'
#' @return The requested provenance object (or `NULL` if not applicable, e.g.,
#'   `extraction_vault()` when `pii_policy = "redact"`).
#'
#' @name extraction_accessors
#' @export
extraction_manifest <- function(x) {
  if (!inherits(x, "airgap_extraction")) {
    cli::cli_abort("{.arg x} must be an `airgap_extraction` object.", class = "airgap_validation_error")
  }
  attr(x, "airgap_manifest")
}

#' @rdname extraction_accessors
#' @export
extraction_privacy_report <- function(x) {
  if (!inherits(x, "airgap_extraction")) {
    cli::cli_abort("{.arg x} must be an `airgap_extraction` object.", class = "airgap_validation_error")
  }
  attr(x, "airgap_privacy_report")
}

#' @rdname extraction_accessors
#' @export
extraction_preflight <- function(x) {
  if (!inherits(x, "airgap_extraction")) {
    cli::cli_abort("{.arg x} must be an `airgap_extraction` object.", class = "airgap_validation_error")
  }
  attr(x, "airgap_preflight")
}

#' @rdname extraction_accessors
#' @export
extraction_vault <- function(x) {
  if (!inherits(x, "airgap_extraction")) {
    cli::cli_abort("{.arg x} must be an `airgap_extraction` object.", class = "airgap_validation_error")
  }
  attr(x, "airgap_vault")
}

#' @rdname extraction_accessors
#' @export
extraction_throughput <- function(x) {
  if (!inherits(x, "airgap_extraction")) {
    cli::cli_abort("{.arg x} must be an `airgap_extraction` object.", class = "airgap_validation_error")
  }
  attr(x, "airgap_throughput")
}
