# Pillar 7 (v0.4.0): Multi-Pass Consensus & Self-Consistency Extraction

#' Clone an airgap_runtime with a fresh seed and isolated mock state for one consensus pass
#' @noRd
clone_runtime_with_seed <- function(runtime, seed) {
  rt <- runtime
  rt$decoding_params$seed <- as.integer(seed)
  if (identical(rt$backend_type, "mock")) {
    st <- new.env(parent = emptyenv())
    st$rows_seen <- character()
    st$call_log <- list()
    rt$state <- st
  }
  rt
}

#' Aggregate a single schema field across multiple extraction passes for one row
#' @noRd
aggregate_field_passes <- function(vals, field, numeric_agg, trim, tie_policy) {
  n_total <- length(vals)
  if (n_total == 0L) {
    return(list(value = typed_na_for_field(field), agreement = NA_real_, tie = FALSE, unanimous = FALSE))
  }

  non_na <- vals[!is.na(vals)]
  if (length(non_na) == 0L) {
    # All successful passes agreed on NA (nullable field)
    return(list(value = typed_na_for_field(field), agreement = 1, tie = FALSE, unanimous = TRUE))
  }

  if (field$type %in% c("character", "enum", "logical")) {
    chr_vals <- as.character(non_na)
    uniq_vals <- unique(chr_vals)
    counts <- vapply(uniq_vals, function(u) sum(chr_vals == u), integer(1L))
    top_cnt <- max(counts)
    winners <- uniq_vals[counts == top_cnt]
    is_tie <- length(winners) > 1L
    agree <- top_cnt / length(non_na)
    unanimous <- length(uniq_vals) == 1L

    if (is_tie && identical(tie_policy, "na")) {
      val <- typed_na_for_field(field)
    } else {
      w <- winners[1L]
      val <- if (identical(field$type, "logical")) as.logical(w) else as.character(w)
    }
    return(list(value = val, agreement = agree, tie = is_tie, unanimous = unanimous))
  }

  # Numeric / integer aggregation
  num_vals <- as.numeric(non_na)
  agg_num <- switch(
    numeric_agg,
    "median" = stats::median(num_vals),
    "trimmed_mean" = mean(num_vals, trim = trim),
    "mean" = mean(num_vals)
  )

  if (identical(field$type, "integer")) {
    agg_val <- as.integer(round(agg_num))
    if (!is.null(field$min)) agg_val <- max(as.integer(ceiling(field$min)), agg_val)
    if (!is.null(field$max)) agg_val <- min(as.integer(floor(field$max)), agg_val)
  } else {
    agg_val <- as.numeric(agg_num)
    if (!is.null(field$min)) agg_val <- max(field$min, agg_val)
    if (!is.null(field$max)) agg_val <- min(field$max, agg_val)
  }

  unanimous <- length(unique(num_vals)) == 1L
  if (unanimous) {
    agree <- 1
  } else if (!is.null(field$min) && !is.null(field$max) && (field$max > field$min)) {
    half_range <- (field$max - field$min) / 2
    mad_val <- mean(abs(num_vals - stats::median(num_vals)))
    agree <- max(0, min(1, 1 - mad_val / half_range))
  } else {
    sd_val <- stats::sd(num_vals)
    scale_ref <- max(1, abs(stats::median(num_vals)))
    agree <- 1 / (1 + sd_val / scale_ref)
  }

  list(value = agg_val, agreement = agree, tie = FALSE, unanimous = unanimous)
}

#' Multi-Pass Consensus & Self-Consistency Structured Batch Extraction
#'
#' Executes deterministic multi-pass local LLM extraction across multiple random
#' seeds and/or prompt template variants, aggregating strictly typed fields via
#' majority vote (`character`, `enum`, `logical`) or robust central tendency
#' (`numeric`, `integer`). Returns a strictly typed consensus `tibble` with
#' per-row agreement scores, per-field consensus diagnostics, and a long-format
#' pass table (`consensus_passes()`) directly compatible with multi-facet
#' psychometric reliability auditing (for example generalizability studies).
#'
#' @param data A data frame containing input text rows.
#' @param text_col Character scalar name of the text column in `data`.
#' @param schema An [extraction_schema()] object.
#' @param runtime A local air-gapped runtime created by [runtime_ollama()],
#'   [runtime_openai_local()], or [runtime_mock()].
#' @param n_passes Integer number of passes when `seeds` is `NULL` (default
#'   `3L`). Must result in at least 2 total passes across seeds and prompts.
#' @param seeds Optional integer vector of explicit decoding seeds. When both
#'   `seeds` and `prompt_templates` are supplied, executes the full crossed
#'   `seeds x prompt_templates` design.
#' @param prompt_templates Optional character vector (named or unnamed) of
#'   prompt templates containing `"{text}"`.
#' @param id_col Optional character scalar column name supplying unique row IDs.
#' @param numeric_agg Aggregation rule for `numeric` and `integer` fields:
#'   `"median"` (default), `"trimmed_mean"`, or `"mean"`.
#' @param trim Fraction of observations trimmed from each end when
#'   `numeric_agg = "trimmed_mean"` (must be in `[0, 0.5)`, default `0.1`).
#' @param tie_policy Tie-breaking policy for categorical/logical majority vote:
#'   `"first"` (default, selects first winning level in pass order) or `"na"`
#'   (returns typed `NA` on exact ties).
#' @param pii_policy Pre-inference privacy policy: `"redact"` (default),
#'   `"pseudonymize"`, or `"verified_deidentified"`.
#' @param pii_config Optional [pii_config()] object.
#' @param pii_key Secret key required when `pii_policy = "pseudonymize"`.
#' @param vault Optional existing `airgap_pii_vault`.
#' @param vault_path Optional destination path for saving the encrypted vault.
#' @param encrypt_vault Logical scalar; encrypt saved vault file. Defaults to
#'   `TRUE`.
#' @param reidentify_output Logical scalar; re-identify character consensus
#'   columns locally when `pii_policy = "pseudonymize"`. Defaults to `FALSE`.
#' @param max_retries Maximum structured repair retries per row per pass
#'   (default `2L`).
#' @param container_spec Optional [airgap_container_spec()].
#' @param model_path Optional local model weight path for pre-flight SHA-256
#'   verification.
#' @param allow_internal_network Logical scalar passed to
#'   [preflight_isolation_check()]. Defaults to `FALSE`.
#' @param strict_proxy Logical scalar passed to [preflight_isolation_check()].
#'   Defaults to `TRUE`.
#' @param output_pii_action Post-inference output PII scan policy: `"redact"`
#'   (default), `"error"`, `"warn"`, or `"none"`.
#' @param audit_log_path Optional path to append a hash-chained consensus run
#'   audit entry.
#' @param run_id Optional run identifier.
#' @param progress Logical scalar; emit brief CLI progress messages. Defaults
#'   to `FALSE`.
#'
#' @return A `tibble` of class `c("airgap_consensus", "tbl_df", "tbl",
#'   "data.frame")` containing the row ID column, strictly typed consensus
#'   schema columns, `.agreement` (row-level mean field agreement in `[0, 1]`),
#'   `.passes_ok`, `.passes_total`, and `.status`. Retrieve the long-format
#'   pass table, per-field diagnostics, and provenance metadata via
#'   [consensus_passes()], [consensus_diagnostics()], and
#'   `attr(res, "airgap_manifest")`.
#'
#' @export
#' @examples
#' data("synthetic_notes", package = "airgapllm")
#' sc <- extraction_schema(
#'   sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
#'   severity = schema_field("integer", min = 0L, max = 10L),
#'   crisis = schema_field("logical")
#' )
#' res <- airgap_extract_consensus(
#'   synthetic_notes[1:4, ],
#'   text_col = "note_text",
#'   schema = sc,
#'   runtime = runtime_mock(seed = 10L),
#'   n_passes = 3L,
#'   id_col = "note_id"
#' )
#' res
#' consensus_diagnostics(res)
#' head(consensus_passes(res))
airgap_extract_consensus <- function(
  data,
  text_col,
  schema,
  runtime,
  n_passes = 3L,
  seeds = NULL,
  prompt_templates = NULL,
  id_col = NULL,
  numeric_agg = c("median", "trimmed_mean", "mean"),
  trim = 0.1,
  tie_policy = c("first", "na"),
  pii_policy = c("redact", "pseudonymize", "verified_deidentified"),
  pii_config = NULL,
  pii_key = NULL,
  vault = NULL,
  vault_path = NULL,
  encrypt_vault = TRUE,
  reidentify_output = FALSE,
  max_retries = 2L,
  container_spec = NULL,
  model_path = NULL,
  allow_internal_network = FALSE,
  strict_proxy = TRUE,
  output_pii_action = c("redact", "error", "warn", "none"),
  audit_log_path = NULL,
  run_id = NULL,
  progress = FALSE
) {
  n_passes_missing <- missing(n_passes)
  output_pii_action_missing <- missing(output_pii_action)
  numeric_agg <- match.arg(numeric_agg)
  tie_policy <- match.arg(tie_policy)
  pii_policy <- match.arg(pii_policy)
  output_pii_action <- match.arg(output_pii_action)

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
  if (!is.numeric(trim) || length(trim) != 1L || is.na(trim) || trim < 0 || trim >= 0.5) {
    cli::cli_abort("{.arg trim} must be a numeric scalar in [0, 0.5).", class = "airgap_validation_error")
  }
  if (is.null(pii_config)) {
    pii_config <- pii_config()
  }
  if (!inherits(pii_config, "airgap_pii_config")) {
    cli::cli_abort("{.arg pii_config} must be an `airgap_pii_config` object.", class = "airgap_validation_error")
  }

  # Resolve crossed pass grid: seeds x prompt_templates
  base_seed <- as.integer(runtime$decoding_params$seed %||% 42L)
  if (!is.null(seeds)) {
    if (!is.numeric(seeds) || length(seeds) == 0L || any(is.na(seeds)) || any(seeds != floor(seeds))) {
      cli::cli_abort("{.arg seeds} must be a non-empty integer vector.", class = "airgap_validation_error")
    }
    eff_seeds <- as.integer(seeds)
  } else if (!is.null(prompt_templates) && isTRUE(n_passes_missing)) {
    eff_seeds <- base_seed
  } else {
    if (!is.numeric(n_passes) || length(n_passes) != 1L || is.na(n_passes) ||
        n_passes < 1 || n_passes != floor(n_passes)) {
      cli::cli_abort("{.arg n_passes} must be a positive integer.", class = "airgap_validation_error")
    }
    eff_seeds <- base_seed + seq_len(as.integer(n_passes)) - 1L
  }

  if (!is.null(prompt_templates)) {
    if (!is.character(prompt_templates) || length(prompt_templates) == 0L ||
        any(is.na(prompt_templates)) || any(!nzchar(trimws(prompt_templates)))) {
      cli::cli_abort("{.arg prompt_templates} must be a non-empty character vector.", class = "airgap_validation_error")
    }
    p_names <- names(prompt_templates)
    if (is.null(p_names) || any(!nzchar(p_names))) {
      p_names <- paste0("P", seq_along(prompt_templates))
    }
    eff_prompts <- stats::setNames(as.list(prompt_templates), p_names)
  } else {
    eff_prompts <- list(P1 = NULL)
  }

  total_passes <- length(eff_seeds) * length(eff_prompts)
  if (total_passes < 2L) {
    cli::cli_abort(
      "Multi-pass consensus requires at least 2 total passes across {.arg seeds}/{.arg n_passes} and {.arg prompt_templates}.",
      class = "airgap_validation_error"
    )
  }

  # 1. Pre-flight check once upfront
  eff_spec <- container_spec %||% runtime$container_spec
  eff_model_digest <- (if (!is.null(eff_spec)) eff_spec$model_digest else NULL) %||% runtime$model_digest
  preflight <- preflight_isolation_check(
    spec = eff_spec,
    endpoint = runtime,
    model_path = model_path,
    expected_model_digest = eff_model_digest,
    allow_internal_network = allow_internal_network,
    strict_proxy = strict_proxy,
    error_on_fail = TRUE
  )

  # 2. Run mandatory PII layer ONCE across input texts so all passes share identical sanitized text & vault
  raw_texts <- normalize_text_utf8(as.character(data[[text_col]]))
  active_vault <- NULL

  if (identical(pii_policy, "redact")) {
    red <- pii_redact(raw_texts, config = pii_config, return_details = TRUE)
    san_texts <- red$text
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
    san_texts <- pse$text
    privacy_report <- pse$report
    active_vault <- pse$vault
  } else {
    san_texts <- raw_texts
    privacy_report <- pii_privacy_report(character(), config = pii_config)
    privacy_report$n_documents <- as.integer(nrow(data))
  }

  san_data <- data
  san_data[[text_col]] <- san_texts
  id_col_name <- id_col %||% ".row_id"
  row_ids <- if (is.null(id_col)) as.character(seq_len(nrow(data))) else as.character(data[[id_col]])
  run_id <- run_id %||% generate_run_id("consensus")

  # Effective output PII scan action per pass
  eff_out_action <- if (identical(pii_policy, "verified_deidentified") && isTRUE(output_pii_action_missing)) {
    "none"
  } else {
    output_pii_action
  }

  # 3. Execute all passes independently on the already-sanitized corpus
  pass_results <- list()
  pass_meta <- list()
  p_idx <- 0L
  t_start <- proc.time()[["elapsed"]]

  for (p_nm in names(eff_prompts)) {
    pt <- eff_prompts[[p_nm]]
    for (sd in eff_seeds) {
      p_idx <- p_idx + 1L
      pid <- sprintf("pass_%02d", p_idx)
      rt_pass <- clone_runtime_with_seed(runtime, sd)

      if (isTRUE(progress)) {
        cli::cli_inform("airgap_extract_consensus [{run_id}]: running {pid} (prompt={p_nm}, seed={sd})...")
      }

      # Text is already sanitized under pii_policy; pass verified_deidentified internally while
      # preserving explicit output_pii_action scanning against the active pii_config
      pass_tbl <- airgap_extract(
        data = san_data,
        text_col = text_col,
        schema = schema,
        runtime = rt_pass,
        prompt_template = pt,
        id_col = id_col,
        pii_policy = "verified_deidentified",
        pii_config = pii_config,
        max_retries = max_retries,
        container_spec = eff_spec,
        model_path = model_path,
        allow_internal_network = allow_internal_network,
        strict_proxy = strict_proxy,
        output_pii_action = eff_out_action,
        progress = FALSE
      )

      pass_results[[pid]] <- pass_tbl
      pass_meta[[pid]] <- list(pass_id = pid, prompt_id = p_nm, seed = as.integer(sd))
    }
  }

  elapsed_sec <- max(proc.time()[["elapsed"]] - t_start, 1e-6)

  # 4. Build long-format pass table directly compatible with psychometric G-study frameworks
  field_names <- names(schema$fields)
  long_parts <- lapply(names(pass_results), function(pid) {
    tbl <- pass_results[[pid]]
    pm <- pass_meta[[pid]]
    n_r <- nrow(tbl)
    base_cols <- list(
      unit_id = as.character(tbl[[id_col_name]]),
      pass_id = rep(pm$pass_id, n_r),
      prompt_id = rep(pm$prompt_id, n_r),
      seed = rep(pm$seed, n_r)
    )
    for (fn in field_names) {
      base_cols[[fn]] <- tbl[[fn]]
    }
    base_cols[[".status"]] <- tbl$.status
    base_cols[[".attempts"]] <- tbl$.attempts
    tibble::as_tibble(base_cols)
  })
  passes_long <- do.call(rbind, long_parts)
  passes_long <- tibble::as_tibble(passes_long)

  # 5. Aggregate consensus row-by-row across all successful passes
  n_rows <- nrow(data)
  out_cols <- list()
  out_cols[[id_col_name]] <- row_ids
  for (fn in field_names) {
    out_cols[[fn]] <- rep(typed_na_for_field(schema$fields[[fn]]), n_rows)
  }

  row_agreement <- rep(NA_real_, n_rows)
  row_passes_ok <- integer(n_rows)
  row_status <- rep("failed", n_rows)

  field_agree_mat <- matrix(NA_real_, nrow = n_rows, ncol = length(field_names),
                            dimnames = list(NULL, field_names))
  field_unanimous_mat <- matrix(NA, nrow = n_rows, ncol = length(field_names),
                                dimnames = list(NULL, field_names))
  field_tie_mat <- matrix(FALSE, nrow = n_rows, ncol = length(field_names),
                          dimnames = list(NULL, field_names))

  for (i in seq_len(n_rows)) {
    ok_passes <- vapply(pass_results, function(tb) identical(tb$.status[i], "ok"), logical(1L))
    n_ok <- sum(ok_passes)
    row_passes_ok[i] <- as.integer(n_ok)
    if (n_ok == 0L) next

    row_status[i] <- "ok"
    ok_list <- pass_results[ok_passes]
    agrees_i <- numeric(length(field_names))

    for (j in seq_along(field_names)) {
      fn <- field_names[j]
      f <- schema$fields[[fn]]
      raw_vals <- unlist(lapply(ok_list, function(tb) tb[[fn]][i]), use.names = FALSE)
      agg <- aggregate_field_passes(raw_vals, f, numeric_agg = numeric_agg, trim = trim, tie_policy = tie_policy)
      out_cols[[fn]][i] <- agg$value
      agrees_i[j] <- agg$agreement
      field_agree_mat[i, j] <- agg$agreement
      field_unanimous_mat[i, j] <- agg$unanimous
      field_tie_mat[i, j] <- agg$tie
    }
    row_agreement[i] <- round(mean(agrees_i, na.rm = TRUE), 4)
  }

  out_cols[[".agreement"]] <- row_agreement
  out_cols[[".passes_ok"]] <- row_passes_ok
  out_cols[[".passes_total"]] <- rep(as.integer(total_passes), n_rows)
  out_cols[[".status"]] <- row_status
  res_tbl <- tibble::as_tibble(out_cols)

  # Optional local re-identification on consensus character columns
  if (isTRUE(reidentify_output) && identical(pii_policy, "pseudonymize") && !is.null(active_vault)) {
    char_cols <- field_names[vapply(schema$fields, function(f) identical(f$type, "character"), logical(1L))]
    if (length(char_cols) > 0L) {
      res_tbl <- pii_reidentify(res_tbl, vault = active_vault, cols = char_cols)
    }
  }

  # 6. Build per-field consensus diagnostics
  diag_tbl <- tibble::tibble(
    field = field_names,
    type = vapply(schema$fields, `[[`, character(1L), "type"),
    n_valid_rows = vapply(seq_along(field_names), function(j) sum(!is.na(field_agree_mat[, j])), integer(1L)),
    mean_agreement = vapply(seq_along(field_names), function(j) {
      v <- field_agree_mat[, j]
      if (all(is.na(v))) NA_real_ else round(mean(v, na.rm = TRUE), 4)
    }, numeric(1L)),
    pct_unanimous = vapply(seq_along(field_names), function(j) {
      v <- field_unanimous_mat[, j]
      v <- v[!is.na(v)]
      if (length(v) == 0L) NA_real_ else round(100 * mean(v), 2)
    }, numeric(1L)),
    n_ties = vapply(seq_along(field_names), function(j) sum(field_tie_mat[, j], na.rm = TRUE), integer(1L))
  )

  # Aggregate output PII leaks & retries across passes
  total_leaks <- sum(vapply(pass_results, function(tb) extraction_throughput(tb)$output_pii_leaks, integer(1L)))
  total_retries <- sum(vapply(pass_results, function(tb) extraction_throughput(tb)$total_retries, integer(1L)))

  pii_counts <- list()
  if (nrow(privacy_report$by_entity) > 0L) {
    for (k in seq_len(nrow(privacy_report$by_entity))) {
      pii_counts[[privacy_report$by_entity$entity_type[k]]] <- as.integer(privacy_report$by_entity$count[k])
    }
  }

  prompt_hashes <- vapply(eff_prompts, function(pt) {
    sha256_string(pt %||% default_prompt_template(schema))
  }, character(1L))

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
      prompt_template_hash = sha256_object(as.list(prompt_hashes)),
      schema_digest = schema$schema_digest,
      decoding_params = c(runtime$decoding_params, list(consensus_passes = as.integer(total_passes), seeds = as.list(eff_seeds))),
      pii_policy = pii_policy,
      pii_config_digest = pii_config$config_digest,
      pii_counts = pii_counts,
      output_pii_leaks = as.integer(total_leaks),
      row_counts = list(
        total = as.integer(n_rows),
        resumed = 0L,
        processed = as.integer(n_rows * total_passes),
        succeeded = as.integer(sum(row_status == "ok")),
        failed = as.integer(sum(row_status != "ok")),
        total_retries = as.integer(total_retries)
      )
    ),
    class = "airgap_run_manifest"
  )

  audit_entry <- NULL
  if (!is.null(audit_log_path)) {
    audit_entry <- audit_log_append(audit_log_path, manifest, event_type = "consensus_extraction_run")
  }

  attr(res_tbl, "airgap_passes") <- passes_long
  attr(res_tbl, "airgap_diagnostics") <- diag_tbl
  attr(res_tbl, "airgap_manifest") <- manifest
  attr(res_tbl, "airgap_privacy_report") <- privacy_report
  attr(res_tbl, "airgap_preflight") <- preflight
  attr(res_tbl, "airgap_vault") <- active_vault
  attr(res_tbl, "airgap_audit_entry") <- audit_entry
  attr(res_tbl, "airgap_consensus_meta") <- list(
    n_passes = as.integer(total_passes),
    seeds = eff_seeds,
    prompt_ids = names(eff_prompts),
    numeric_agg = numeric_agg,
    tie_policy = tie_policy,
    elapsed_sec = round(elapsed_sec, 4)
  )
  class(res_tbl) <- c("airgap_consensus", class(res_tbl))

  res_tbl
}

#' Access Long-Format Passes and Per-Field Diagnostics from Consensus Extractions
#'
#' Retrieves the long-format pass table (`unit_id`, `pass_id`, `prompt_id`,
#' `seed`, and all extracted fields—directly compatible with multi-facet
#' psychometric reliability modeling such as generalizability studies) or the
#' per-field agreement summary table from an [airgap_extract_consensus()]
#' result.
#'
#' @param x An `airgap_consensus` tibble returned by
#'   [airgap_extract_consensus()].
#'
#' @return A `tibble` of individual pass outputs (`consensus_passes()`) or
#'   per-field agreement diagnostics (`consensus_diagnostics()`).
#'
#' @name consensus_accessors
#' @export
#' @examples
#' df <- tibble::tibble(id = c("R1", "R2"), txt = c("Calm mood.", "Mild worry."))
#' sc <- extraction_schema(mood = schema_field("enum", values = c("calm", "worried")))
#' res <- airgap_extract_consensus(df, "txt", sc, runtime_mock(), n_passes = 3L, id_col = "id")
#' consensus_diagnostics(res)
#' consensus_passes(res)
consensus_passes <- function(x) {
  if (!inherits(x, "airgap_consensus")) {
    cli::cli_abort("{.arg x} must be an `airgap_consensus` object.", class = "airgap_validation_error")
  }
  attr(x, "airgap_passes")
}

#' @rdname consensus_accessors
#' @export
consensus_diagnostics <- function(x) {
  if (!inherits(x, "airgap_consensus")) {
    cli::cli_abort("{.arg x} must be an `airgap_consensus` object.", class = "airgap_validation_error")
  }
  attr(x, "airgap_diagnostics")
}
