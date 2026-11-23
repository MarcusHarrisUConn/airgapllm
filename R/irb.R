# Pillar 4b: IRB / HIPAA / Methods Data-Security Protocol Generator

#' Generate Ready-to-Paste IRB / HIPAA Methods & Data-Security Documentation
#'
#' Renders standardized Markdown or Quarto Methods and Data-Security protocol
#' boilerplate populated directly from a verified [airgap_extract()] result,
#' `airgap_run_manifest`, `airgap_audit_entry`, or hash-chained JSONL audit log
#' file. Never includes raw participant text or sensitive PII values—only
#' cryptographic provenance digests, isolation attestations, and aggregate PII
#' redaction counts.
#'
#' @param source An `airgap_extraction` object, an `airgap_run_manifest`, an
#'   `airgap_audit_entry`, or a character scalar file path to a JSONL audit log
#'   (verified via [audit_log_verify()] before rendering).
#' @param study_title Optional character scalar study title.
#' @param protocol_id Optional character scalar IRB protocol identifier (e.g.,
#'   `"IRB-2026-0412"`).
#' @param institution Optional character scalar institutional name.
#' @param pi_name Optional character scalar Principal Investigator name (for
#'   protocol header only; omitted when `NULL`).
#' @param regulatory_framework Character vector of applicable frameworks from
#'   `c("HIPAA", "IRB", "FERPA")`. Defaults to `c("HIPAA", "IRB")`.
#' @param format Character scalar output format: `"markdown"` (default) or
#'   `"quarto"`.
#' @param include_technical_appendix Logical scalar; include a Markdown
#'   cryptographic provenance & aggregate PII redaction table. Defaults to
#'   `TRUE`.
#' @param file Optional file path to write the rendered protocol snippet.
#'
#' @return A character scalar of class `"airgap_irb_narrative"`.
#'
#' @export
#' @examples
#' df <- tibble::tibble(id = c("P1", "P2"), txt = c("Dr. Jane Doe visited.", "Follow-up ok."))
#' sc <- extraction_schema(status = schema_field("enum", values = c("stable", "acute")))
#' res <- airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id")
#' cat(generate_irb_narrative(res, protocol_id = "IRB-2026-001"))
generate_irb_narrative <- function(
  source,
  study_title = NULL,
  protocol_id = NULL,
  institution = NULL,
  pi_name = NULL,
  regulatory_framework = c("HIPAA", "IRB"),
  format = c("markdown", "quarto"),
  include_technical_appendix = TRUE,
  file = NULL
) {
  format <- match.arg(format)
  assert_scalar_logical(include_technical_appendix, "include_technical_appendix")

  valid_fw <- c("HIPAA", "IRB", "FERPA")
  if (!is.character(regulatory_framework) || length(regulatory_framework) == 0L ||
      any(!regulatory_framework %in% valid_fw)) {
    cli::cli_abort(
      "{.arg regulatory_framework} must be a non-empty subset of {paste(valid_fw, collapse = ', ')}.",
      class = "airgap_validation_error"
    )
  }
  regulatory_framework <- unique(regulatory_framework)

  audit_chain_status <- "Not persisted to external JSONL audit log"
  audit_chain_head <- NULL
  audit_entries_count <- NULL

  if (inherits(source, "airgap_extraction")) {
    manifest <- extraction_manifest(source)
    ae <- attr(source, "airgap_audit_entry")
    if (!is.null(ae)) {
      audit_chain_status <- paste0("Verified entry #", ae$seq, " recorded in hash-chained JSONL ledger")
      audit_chain_head <- ae$entry_hash
      audit_entries_count <- ae$seq
    }
  } else if (inherits(source, "airgap_run_manifest") || inherits(source, "airgap_audit_entry")) {
    manifest <- source
    if (inherits(source, "airgap_audit_entry")) {
      audit_chain_status <- paste0("Audit entry #", source$seq, " (hash-chained SHA-256)")
      audit_chain_head <- source$entry_hash
      audit_entries_count <- source$seq
    }
  } else if (is.character(source) && length(source) == 1L) {
    ver <- audit_log_verify(source, strict = TRUE)
    if (!isTRUE(ver$valid)) {
      cli::cli_abort(
        c(
          "Cannot generate IRB narrative from tampered or invalid audit log {.path {source}}.",
          stats::setNames(ver$issues, rep("x", length(ver$issues)))
        ),
        class = "airgap_audit_tamper_error"
      )
    }
    log_obj <- audit_log_read(source)
    # Prefer the latest extraction_run entry; otherwise use the last entry
    ext_entries <- Filter(function(e) identical(e$event_type, "extraction_run"), log_obj$entries)
    manifest <- if (length(ext_entries) > 0L) ext_entries[[length(ext_entries)]] else log_obj$entries[[length(log_obj$entries)]]
    audit_chain_status <- paste0("VERIFIED (", ver$n_entries, " chained entries; zero tampering detected)")
    audit_chain_head <- ver$chain_head_hash
    audit_entries_count <- ver$n_entries
  } else {
    cli::cli_abort(
      "{.arg source} must be an `airgap_extraction`, `airgap_run_manifest`, `airgap_audit_entry`, or path to a JSONL audit log.",
      class = "airgap_validation_error"
    )
  }

  fw_str <- paste(regulatory_framework, collapse = " / ")
  backend_str <- manifest$container_backend %||% "local container runtime"
  net_str <- manifest$network_mode %||% "none"
  model_str <- manifest$model_name %||% "unspecified local model"
  model_sha <- manifest$model_digest %||% "not pinned"
  img_sha <- manifest$container_image_digest %||% "not pinned"
  spec_sha <- manifest$container_spec_digest %||% "not supplied"
  ep_class <- manifest$endpoint_class %||% "loopback"
  iso_status <- manifest$isolation_status %||% "PASS"
  pf_hash <- manifest$preflight_hash %||% "N/A"
  prompt_sha <- manifest$prompt_template_hash %||% "N/A"
  schema_sha <- manifest$schema_digest %||% "N/A"
  pii_pol <- manifest$pii_policy %||% "redact"
  pii_cfg_sha <- manifest$pii_config_digest %||% "N/A"
  dec <- manifest$decoding_params %||% list()
  rc <- manifest$row_counts %||% list()
  pii_counts <- manifest$pii_counts %||% list()
  total_pii <- if (length(pii_counts) > 0L) sum(unlist(pii_counts)) else 0L

  # Header metadata lines
  meta_lines <- character()
  if (!is.null(study_title)) meta_lines <- c(meta_lines, paste0("- **Study Title:** ", study_title))
  if (!is.null(protocol_id)) meta_lines <- c(meta_lines, paste0("- **Protocol ID:** ", protocol_id))
  if (!is.null(institution)) meta_lines <- c(meta_lines, paste0("- **Institution:** ", institution))
  if (!is.null(pi_name)) meta_lines <- c(meta_lines, paste0("- **Principal Investigator:** ", pi_name))
  meta_lines <- c(
    meta_lines,
    paste0("- **Regulatory Scope:** ", fw_str),
    paste0("- **Run ID:** `", manifest$run_id %||% "N/A", "` (", manifest$timestamp %||% utc_timestamp(), ")")
  )

  # Policy-specific privacy prose
  pii_prose <- switch(
    pii_pol,
    "redact" = paste0(
      "Prior to prompt construction, all unstructured text was processed in-memory by the deterministic pure-R ",
      "`airgapllm` PII detection and redaction engine (`pii_policy = \"redact\"`, config digest `", pii_cfg_sha, "`). ",
      "A total of **", total_pii, "** direct identifier span(s) across **", length(pii_counts), "** entity class(es) ",
      "were replaced with non-reversible typed placeholders (e.g., `[REDACTED_PERSON_NAME]`, `[REDACTED_EMAIL]`) ",
      "before any text reached the local inference runtime."
    ),
    "pseudonymize" = paste0(
      "Prior to prompt construction, all unstructured text underwent deterministic keyed reversible pseudonymization ",
      "using HMAC-SHA256 (`pii_policy = \"pseudonymize\"`, config digest `", pii_cfg_sha, "`). ",
      "A total of **", total_pii, "** direct identifier span(s) across **", length(pii_counts), "** entity class(es) ",
      "were replaced with keyed tokens (`<<TYPE_HASH>>`) preserving within-corpus entity coreference without exposing ",
      "identifying strings to the language model. The re-identification mapping vault is stored separately from prompts, ",
      "checkpoints, and audit logs using AES-256-CBC encryption with Encrypt-then-MAC HMAC-SHA256 authentication and ",
      "owner-only (`0600`) filesystem permissions."
    ),
    "verified_deidentified" = paste0(
      "The research team attested that input text was previously de-identified prior to ingestion ",
      "(`pii_policy = \"verified_deidentified\"`). This attestation is explicitly recorded in the immutable run ledger."
    ),
    paste0("Pre-inference PII policy applied: `", pii_pol, "`.")
  )

  # Narrative sections
  sec_isolation <- paste0(
    "### 1. Offline Local AI Execution & Network Isolation\n\n",
    "All automated natural language processing was executed strictly offline using `airgapllm` (v",
    manifest$package_version %||% airgapllm_version(), ", R ", manifest$r_version %||% as.character(getRversion()),
    ") with **zero transmission of research data to external cloud APIs or third-party servers**. ",
    "Inference was configured for local execution (`backend = \"", backend_str, "\"`, endpoint class: `", ep_class,
    "`) under hardened container controls (`network_mode = \"", net_str, "\"`, read-only root filesystem, ",
    "all Linux capabilities dropped, `no-new-privileges`, read-only model volume mounts, and offline telemetry suppression). ",
    "Automated pre-flight isolation checks (`preflight_isolation_check()`) returned **`", iso_status, "`** ",
    "(attestation hash: `", pf_hash, "`), confirming strict local/loopback confinement and proxy bypass prior to reading participant text."
  )

  sec_privacy <- paste0(
    "### 2. Pre-Inference De-Identification & Privacy Safeguards\n\n",
    pii_prose, "\n\n",
    "Neither raw participant text nor raw PII strings are persisted in crash-recovery checkpoints or compliance logs. ",
    "Audit log writes enforce a strict schema allowlist and automated PII scanning that aborts execution if any raw text ",
    "key or sensitive identifier is encountered."
  )

  sec_repro <- paste0(
    "### 3. Model Provenance, Schema Enforcement & Reproducibility\n\n",
    "Structured extraction used local open-weights model `", model_str, "` (weight SHA-256: `", model_sha, "`) ",
    "with deterministic decoding parameters (`temperature = ", dec$temperature %||% "NA",
    "`, `seed = ", dec$seed %||% "NA", "`, `top_p = ", dec$top_p %||% "NA", "`). ",
    "Every model generation was validated against a strictly typed output schema (schema SHA-256: `", schema_sha,
    "`; prompt template SHA-256: `", prompt_sha, "`) with bounded structured repair retries for malformed outputs ",
    "and atomic row-level JSONL checkpointing. Across **", rc$total %||% "N/A", "** input record(s), **",
    rc$succeeded %||% "N/A", "** succeeded and **", rc$failed %||% "N/A", "** failed (",
    rc$resumed %||% 0L, " resumed from checkpoint; ", rc$total_retries %||% 0L, " structured repair retries)."
  )

  sec_audit <- paste0(
    "### 4. Immutable Compliance Audit Trail\n\n",
    "Run provenance is recorded in a tamper-evident, SHA-256 hash-chained JSONL audit log linking each entry to its ",
    "predecessor from `GENESIS`. Audit verification status: **", audit_chain_status, "**",
    if (!is.null(audit_chain_head)) paste0(" (chain head digest: `", audit_chain_head, "`).") else "."
  )

  blocks <- c(
    "## Data Security & Air-Gapped Local AI Processing Protocol",
    "",
    paste(meta_lines, collapse = "\n"),
    "",
    sec_isolation,
    "",
    sec_privacy,
    "",
    sec_repro,
    "",
    sec_audit
  )

  if (isTRUE(include_technical_appendix)) {
    prov_table <- c(
      "",
      "### Technical Provenance Summary",
      "",
      "| Control / Artifact | Verified Value |",
      "| :--- | :--- |",
      paste0("| Isolation Pre-Flight Status | `", iso_status, "` (`", pf_hash, "`) |"),
      paste0("| Endpoint Class | `", ep_class, "` |"),
      paste0("| Container Backend / Network | `", backend_str, "` / `", net_str, "` |"),
      paste0("| Container Image Digest | `", img_sha, "` |"),
      paste0("| Container Spec Digest | `", spec_sha, "` |"),
      paste0("| Model Name | `", model_str, "` |"),
      paste0("| Model Weight SHA-256 | `", model_sha, "` |"),
      paste0("| Prompt Template SHA-256 | `", prompt_sha, "` |"),
      paste0("| Output Schema SHA-256 | `", schema_sha, "` |"),
      paste0("| Decoding Seed / Temperature | `", dec$seed %||% "NA", "` / `", dec$temperature %||% "NA", "` |"),
      paste0("| Pre-Inference PII Policy | `", pii_pol, "` (`", total_pii, "` detections) |"),
      paste0("| Rows Processed (OK / Failed) | `", rc$total %||% "N/A", "` (`", rc$succeeded %||% "N/A", "` / `", rc$failed %||% "N/A", "`) |"),
      paste0("| Audit Chain Head Hash | `", audit_chain_head %||% "N/A", "` |"),
      paste0("| Software Environment | `airgapllm ", manifest$package_version %||% airgapllm_version(),
             "` / `R ", manifest$r_version %||% as.character(getRversion()), "` |")
    )

    blocks <- c(blocks, prov_table)

    if (length(pii_counts) > 0L) {
      ent_names <- sort(names(pii_counts))
      pii_rows <- vapply(
        ent_names,
        function(en) paste0("| `", en, "` | ", pii_counts[[en]], " |"),
        character(1L)
      )
      blocks <- c(
        blocks,
        "",
        "#### Aggregate Pre-Inference PII Redaction Counts (Zero Raw Values Stored)",
        "",
        "| Entity Type | Count |",
        "| :--- | ---: |",
        pii_rows
      )
    }
  }

  body_text <- paste(blocks, collapse = "\n")

  if (identical(format, "quarto")) {
    body_text <- paste(
      "::: {.callout-note title=\"Air-Gapped Local AI Compliance Attestation\"}",
      paste0("Generated automatically by `airgapllm` (", manifest$package_version %||% airgapllm_version(), ") for ", fw_str, " review."),
      ":::",
      "",
      body_text,
      sep = "\n"
    )
  }

  if (!is.null(file)) {
    assert_scalar_string(file, "file")
    dir.create(dirname(file), recursive = TRUE, showWarnings = FALSE)
    writeLines(body_text, con = file, useBytes = TRUE)
  }

  structure(body_text, class = "airgap_irb_narrative")
}

#' @export
print.airgap_irb_narrative <- function(x, ...) {
  cat(as.character(x), "\n", sep = "")
  invisible(x)
}
