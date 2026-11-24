# Pillar 6 (v0.4.0): Quasi-Identifier & k-Anonymity / l-Diversity Risk Auditor

#' Build composite equivalence class keys across quasi-identifier columns
#' @noRd
build_equivalence_keys <- function(data, quasi_ids, include_na = TRUE) {
  n <- nrow(data)
  if (n == 0L) {
    return(list(keys = character(), excluded = logical()))
  }

  cols_chr <- vector("list", length(quasi_ids))
  has_na <- rep(FALSE, n)
  for (j in seq_along(quasi_ids)) {
    v <- data[[quasi_ids[j]]]
    na_j <- is.na(v)
    has_na <- has_na | na_j
    s <- as.character(v)
    s[na_j] <- "<NA>"
    cols_chr[[j]] <- s
  }

  keys <- do.call(paste, c(cols_chr, list(sep = "\x1f")))
  if (!isTRUE(include_na)) {
    keys[has_na] <- NA_character_
    return(list(keys = keys, excluded = has_na))
  }
  list(keys = keys, excluded = rep(FALSE, n))
}

#' Assess Quasi-Identifier Re-Identification Risk (k-Anonymity & l-Diversity)
#'
#' Audits an extracted or clinical data frame across user-specified
#' quasi-identifiers (for example `age_band`, `zip3`, `gender`, `site`) to
#' quantify $k$-anonymity compliance, prosecutor and journalist
#' re-identification risks, sample uniqueness, and optional distinct
#' $l$-diversity for a sensitive outcome column. Equivalence class diagnostics
#' use opaque integer class IDs and aggregate counts only—never logging raw
#' participant records.
#'
#' @param data A data frame or tibble to audit.
#' @param quasi_ids Character vector of one or more quasi-identifier column
#'   names present in `data`.
#' @param k_min Integer minimum required equivalence class size (must be
#'   `>= 2L`, default `5L`).
#' @param sensitive_col Optional character scalar name of a sensitive outcome
#'   column in `data` for distinct $l$-diversity auditing.
#' @param l_min Integer minimum required number of distinct non-NA values of
#'   `sensitive_col` within every equivalence class (must be `>= 2L`, default
#'   `2L`). Ignored when `sensitive_col = NULL`.
#' @param sampling_fraction Numeric population sampling fraction in `(0, 1]`
#'   used to compute conservative journalist re-identification risk upper
#'   bounds (`min(1, sampling_fraction / k)`). Defaults to `1` (conservative
#'   full-population / census upper bound equal to prosecutor risk).
#' @param include_na Logical scalar; if `TRUE` (default), `NA` values in
#'   `quasi_ids` form their own equivalence category (`"<NA>"`). If `FALSE`,
#'   rows containing `NA` in any quasi-identifier are excluded from equivalence
#'   class grouping and reported in `n_rows_excluded_na`.
#'
#' @return An S3 object of class `"airgap_reid_risk"` containing:
#'   - `n_rows`, `n_rows_evaluated`, `n_rows_excluded_na`, `n_classes`
#'   - `quasi_ids`, `k_min`, `min_k`, `median_k`
#'   - `n_unique_rows`, `pct_unique_rows`
#'   - `n_violating_classes`, `n_violating_rows`, `pct_violating_rows`
#'   - `passes_k_anonymity` (logical)
#'   - `prosecutor_risk_max`, `prosecutor_risk_mean`
#'   - `journalist_risk_max`, `journalist_risk_mean`, `sampling_fraction`
#'   - `sensitive_col`, `l_min`, `min_l`, `n_l_violating_classes`,
#'     `n_l_violating_rows`, `pct_l_violating_rows`, `passes_l_diversity`
#'   - `equivalence_classes`: privacy-safe tibble indexed by opaque `class_id`
#'   - `row_class_size`: integer vector of class sizes aligned to `data` rows
#'   - `row_violates`: logical vector flagging rows failing $k$-anonymity (or
#'     $l$-diversity when `sensitive_col` is supplied)
#'
#' @export
#' @examples
#' df <- tibble::tibble(
#'   site = c(rep("North", 6), rep("South", 2), rep("West", 5)),
#'   wave = c(rep(1L, 6), rep(2L, 2), rep(1L, 5)),
#'   diagnosis = c("A", "B", "A", "B", "C", "A", "A", "A", "B", "C", "B", "C", "A")
#' )
#' assess_reidentification_risk(df, quasi_ids = c("site", "wave"),
#'                              k_min = 5L, sensitive_col = "diagnosis", l_min = 2L)
assess_reidentification_risk <- function(
  data,
  quasi_ids,
  k_min = 5L,
  sensitive_col = NULL,
  l_min = 2L,
  sampling_fraction = 1,
  include_na = TRUE
) {
  if (!is.data.frame(data)) {
    cli::cli_abort("{.arg data} must be a data frame or tibble.", class = "airgap_validation_error")
  }
  if (!is.character(quasi_ids) || length(quasi_ids) == 0L || any(is.na(quasi_ids)) || any(!nzchar(trimws(quasi_ids)))) {
    cli::cli_abort("{.arg quasi_ids} must be a non-empty character vector of column names.", class = "airgap_validation_error")
  }
  quasi_ids <- unique(quasi_ids)
  missing_q <- setdiff(quasi_ids, names(data))
  if (length(missing_q) > 0L) {
    cli::cli_abort(
      "Quasi-identifier column(s) not found in {.arg data}: {paste(missing_q, collapse = ', ')}.",
      class = "airgap_validation_error"
    )
  }

  if (!is.numeric(k_min) || length(k_min) != 1L || is.na(k_min) || k_min < 2 || k_min != floor(k_min)) {
    cli::cli_abort("{.arg k_min} must be an integer >= 2.", class = "airgap_validation_error")
  }
  k_min <- as.integer(k_min)

  if (!is.null(sensitive_col)) {
    assert_scalar_string(sensitive_col, "sensitive_col")
    if (!sensitive_col %in% names(data)) {
      cli::cli_abort("Column {.val {sensitive_col}} not found in {.arg data}.", class = "airgap_validation_error")
    }
    if (sensitive_col %in% quasi_ids) {
      cli::cli_abort("{.arg sensitive_col} must not overlap with {.arg quasi_ids}.", class = "airgap_validation_error")
    }
    if (!is.numeric(l_min) || length(l_min) != 1L || is.na(l_min) || l_min < 2 || l_min != floor(l_min)) {
      cli::cli_abort("{.arg l_min} must be an integer >= 2.", class = "airgap_validation_error")
    }
    l_min <- as.integer(l_min)
  } else {
    l_min <- NA_integer_
  }

  if (!is.numeric(sampling_fraction) || length(sampling_fraction) != 1L ||
      is.na(sampling_fraction) || !is.finite(sampling_fraction) ||
      sampling_fraction <= 0 || sampling_fraction > 1) {
    cli::cli_abort("{.arg sampling_fraction} must be a finite number in (0, 1].", class = "airgap_validation_error")
  }
  assert_scalar_logical(include_na, "include_na")

  n_total <- nrow(data)
  eq <- build_equivalence_keys(data, quasi_ids, include_na = include_na)
  eval_idx <- which(!eq$excluded)
  n_eval <- length(eval_idx)
  n_excl <- as.integer(n_total - n_eval)

  if (n_eval == 0L) {
    empty_tbl <- tibble::tibble(
      class_id = integer(),
      class_size = integer(),
      k_violation = logical(),
      prosecutor_risk = numeric(),
      journalist_risk = numeric(),
      l_distinct = integer(),
      l_violation = logical()
    )
    return(structure(
      list(
        n_rows = as.integer(n_total),
        n_rows_evaluated = 0L,
        n_rows_excluded_na = n_excl,
        n_classes = 0L,
        quasi_ids = quasi_ids,
        k_min = k_min,
        min_k = NA_integer_,
        median_k = NA_real_,
        n_unique_rows = 0L,
        pct_unique_rows = 0,
        n_violating_classes = 0L,
        n_violating_rows = 0L,
        pct_violating_rows = 0,
        passes_k_anonymity = TRUE,
        prosecutor_risk_max = 0,
        prosecutor_risk_mean = 0,
        journalist_risk_max = 0,
        journalist_risk_mean = 0,
        sampling_fraction = sampling_fraction,
        sensitive_col = sensitive_col,
        l_min = l_min,
        min_l = NA_integer_,
        n_l_violating_classes = 0L,
        n_l_violating_rows = 0L,
        pct_l_violating_rows = 0,
        passes_l_diversity = if (is.null(sensitive_col)) NA else TRUE,
        equivalence_classes = empty_tbl,
        row_class_size = rep(NA_integer_, n_total),
        row_violates = rep(FALSE, n_total),
        assessed_at = utc_timestamp()
      ),
      class = "airgap_reid_risk"
    ))
  }

  eval_keys <- eq$keys[eval_idx]
  uniq_keys <- unique(eval_keys)
  cls_idx <- match(eval_keys, uniq_keys)
  cls_sizes <- tabulate(cls_idx, nbins = length(uniq_keys))

  row_k_eval <- cls_sizes[cls_idx]
  row_k_all <- rep(NA_integer_, n_total)
  row_k_all[eval_idx] <- as.integer(row_k_eval)

  cls_k_viol <- cls_sizes < k_min
  row_k_viol_eval <- row_k_eval < k_min

  cls_pros_risk <- 1 / cls_sizes
  cls_jour_risk <- pmin(1, sampling_fraction / cls_sizes)

  # Optional distinct l-diversity
  if (!is.null(sensitive_col)) {
    sens_eval <- data[[sensitive_col]][eval_idx]
    cls_l <- vapply(seq_along(uniq_keys), function(cid) {
      vals <- sens_eval[cls_idx == cid]
      vals <- vals[!is.na(vals)]
      length(unique(vals))
    }, integer(1L))
    cls_l_viol <- cls_l < l_min
    row_l_viol_eval <- cls_l_viol[cls_idx]
    min_l <- min(cls_l)
    n_l_viol_cls <- sum(cls_l_viol)
    n_l_viol_rows <- sum(row_l_viol_eval)
    pct_l_viol_rows <- round(100 * n_l_viol_rows / n_eval, 2)
    passes_l <- n_l_viol_rows == 0L
  } else {
    cls_l <- rep(NA_integer_, length(uniq_keys))
    cls_l_viol <- rep(NA, length(uniq_keys))
    row_l_viol_eval <- rep(FALSE, n_eval)
    min_l <- NA_integer_
    n_l_viol_cls <- 0L
    n_l_viol_rows <- 0L
    pct_l_viol_rows <- 0
    passes_l <- NA
  }

  row_viol_all <- rep(FALSE, n_total)
  row_viol_all[eval_idx] <- row_k_viol_eval | row_l_viol_eval

  ord_cls <- order(cls_sizes, seq_along(cls_sizes))
  eq_tbl <- tibble::tibble(
    class_id = seq_along(ord_cls),
    class_size = as.integer(cls_sizes[ord_cls]),
    k_violation = cls_k_viol[ord_cls],
    prosecutor_risk = round(cls_pros_risk[ord_cls], 4),
    journalist_risk = round(cls_jour_risk[ord_cls], 4),
    l_distinct = as.integer(cls_l[ord_cls]),
    l_violation = as.logical(cls_l_viol[ord_cls])
  )

  n_unique <- sum(row_k_eval == 1L)
  n_viol_rows <- sum(row_k_viol_eval)

  structure(
    list(
      n_rows = as.integer(n_total),
      n_rows_evaluated = as.integer(n_eval),
      n_rows_excluded_na = n_excl,
      n_classes = as.integer(length(uniq_keys)),
      quasi_ids = quasi_ids,
      k_min = k_min,
      min_k = as.integer(min(cls_sizes)),
      median_k = as.numeric(stats::median(cls_sizes)),
      n_unique_rows = as.integer(n_unique),
      pct_unique_rows = round(100 * n_unique / n_eval, 2),
      n_violating_classes = as.integer(sum(cls_k_viol)),
      n_violating_rows = as.integer(n_viol_rows),
      pct_violating_rows = round(100 * n_viol_rows / n_eval, 2),
      passes_k_anonymity = n_viol_rows == 0L,
      prosecutor_risk_max = round(max(cls_pros_risk), 4),
      prosecutor_risk_mean = round(mean(1 / row_k_eval), 4),
      journalist_risk_max = round(max(cls_jour_risk), 4),
      journalist_risk_mean = round(mean(pmin(1, sampling_fraction / row_k_eval)), 4),
      sampling_fraction = sampling_fraction,
      sensitive_col = sensitive_col,
      l_min = l_min,
      min_l = as.integer(min_l),
      n_l_violating_classes = as.integer(n_l_viol_cls),
      n_l_violating_rows = as.integer(n_l_viol_rows),
      pct_l_violating_rows = pct_l_viol_rows,
      passes_l_diversity = passes_l,
      equivalence_classes = eq_tbl,
      row_class_size = row_k_all,
      row_violates = row_viol_all,
      assessed_at = utc_timestamp()
    ),
    class = "airgap_reid_risk"
  )
}

#' @export
print.airgap_reid_risk <- function(x, ...) {
  k_tag <- if (isTRUE(x$passes_k_anonymity)) "PASS" else "FAIL"
  cat("<airgap_reid_risk> [k-anonymity (k>=", x$k_min, "): ", k_tag, "]\n", sep = "")
  cat("  Quasi-identifiers:   ", paste(x$quasi_ids, collapse = ", "), "\n", sep = "")
  cat("  Rows evaluated:      ", x$n_rows_evaluated, " / ", x$n_rows,
      " across ", x$n_classes, " equivalence class(es)\n", sep = "")
  cat("  Min / Median k:      ", x$min_k, " / ", x$median_k, "\n", sep = "")
  cat("  Sample uniques (k=1):", x$n_unique_rows, " (", x$pct_unique_rows, "%)\n", sep = "")
  cat("  Rows with k < ", x$k_min, ":     ", x$n_violating_rows, " (",
      x$pct_violating_rows, "%)\n", sep = "")
  cat("  Prosecutor risk:     max=", sprintf("%.4f", x$prosecutor_risk_max),
      " | mean=", sprintf("%.4f", x$prosecutor_risk_mean), "\n", sep = "")
  cat("  Journalist risk:     max=", sprintf("%.4f", x$journalist_risk_max),
      " | mean=", sprintf("%.4f", x$journalist_risk_mean),
      " (f=", x$sampling_fraction, ")\n", sep = "")
  if (!is.null(x$sensitive_col)) {
    l_tag <- if (isTRUE(x$passes_l_diversity)) "PASS" else "FAIL"
    cat("  l-diversity ('", x$sensitive_col, "', l>=", x$l_min, "): ", l_tag,
        " (min_l=", x$min_l, ", violating rows=", x$n_l_violating_rows,
        " [", x$pct_l_violating_rows, "%])\n", sep = "")
  }
  invisible(x)
}

#' Enforce k-Anonymity (and Optional l-Diversity) on a Research Table
#'
#' Applies safe row suppression (`"suppress_rows"`) or rare-class masking
#' (`"mask_rare"`) to eliminate equivalence classes violating `k_min` (and
#' optionally `l_min` distinct values of `sensitive_col`). Under `"mask_rare"`,
#' if the masked fallback class itself has fewer than `k_min` rows, additional
#' smallest equivalence classes are progressively generalized into `mask_value`
#' until the masked class meets `k_min` (preventing residual sub-`k` leakage).
#' Returns the privacy-safe data frame together with a before/after risk
#' reduction summary without ever logging raw participant values.
#'
#' @param data A data frame or tibble.
#' @param quasi_ids Character vector of quasi-identifier column names.
#' @param k_min Integer minimum required equivalence class size (`>= 2L`,
#'   default `5L`).
#' @param strategy Character scalar de-identification strategy:
#'   `"suppress_rows"` (default, removes violating rows) or `"mask_rare"`
#'   (replaces quasi-identifiers of violating rows with `mask_value`).
#' @param mask_value Character scalar replacement value used when
#'   `strategy = "mask_rare"` (default `"[SUPPRESSED]"`).
#' @param sensitive_col Optional character scalar sensitive outcome column for
#'   $l$-diversity enforcement.
#' @param l_min Integer minimum required distinct values of `sensitive_col`
#'   per class (`>= 2L`, default `2L`).
#' @param include_na Logical scalar passed to [assess_reidentification_risk()].
#'   Defaults to `TRUE`.
#'
#' @return An S3 object of class `"airgap_k_anonymized"` containing `data`
#'   (privacy-safe tibble), `strategy`, `k_min`, `l_min`, `n_rows_before`,
#'   `n_rows_after`, `n_rows_suppressed`, `n_rows_masked`, `risk_before`, and
#'   `risk_after`.
#'
#' @export
#' @examples
#' df <- tibble::tibble(
#'   site = c(rep("North", 6), rep("South", 2), rep("West", 5)),
#'   wave = c(rep(1L, 6), rep(2L, 2), rep(1L, 5)),
#'   score = seq_len(13)
#' )
#' res <- apply_k_anonymity(df, quasi_ids = c("site", "wave"), k_min = 5L)
#' res
apply_k_anonymity <- function(
  data,
  quasi_ids,
  k_min = 5L,
  strategy = c("suppress_rows", "mask_rare"),
  mask_value = "[SUPPRESSED]",
  sensitive_col = NULL,
  l_min = 2L,
  include_na = TRUE
) {
  strategy <- match.arg(strategy)
  if (!is.na(mask_value)) {
    assert_scalar_string(mask_value, "mask_value")
  } else {
    mask_value <- NA_character_
  }

  risk_before <- assess_reidentification_risk(
    data = data,
    quasi_ids = quasi_ids,
    k_min = k_min,
    sensitive_col = sensitive_col,
    l_min = l_min,
    include_na = include_na
  )

  safe_df <- tibble::as_tibble(data)
  viol_mask <- risk_before$row_violates
  n_suppressed <- 0L
  n_masked <- 0L

  if (any(viol_mask)) {
    if (identical(strategy, "suppress_rows")) {
      keep <- !viol_mask
      n_suppressed <- as.integer(sum(viol_mask))
      safe_df <- safe_df[keep, , drop = FALSE]
    } else {
      # Strategy: mask_rare with iterative protection against sub-k masked residual class
      masked_rows <- viol_mask
      eq <- build_equivalence_keys(safe_df, quasi_ids, include_na = include_na)

      # If masked_rows alone forms a class smaller than k_min (and dataset has >= k_min rows),
      # progressively absorb the smallest remaining equivalence class(es) into the masked class
      # so the final masked class itself satisfies k >= k_min (and l >= l_min if requested).
      if (nrow(safe_df) >= k_min) {
        for (iter in seq_len(max(1L, risk_before$n_classes))) {
          cur_masked_n <- sum(masked_rows)
          l_ok <- TRUE
          if (!is.null(sensitive_col) && cur_masked_n > 0L) {
            vals <- safe_df[[sensitive_col]][masked_rows]
            vals <- vals[!is.na(vals)]
            l_ok <- length(unique(vals)) >= l_min
          }
          if (cur_masked_n >= k_min && l_ok) break

          rem_idx <- which(!masked_rows & !eq$excluded)
          if (length(rem_idx) == 0L) break
          rem_keys <- eq$keys[rem_idx]
          tbl_rem <- table(rem_keys)
          smallest_key <- names(tbl_rem)[which.min(tbl_rem)]
          masked_rows[eq$keys == smallest_key] <- TRUE
        }
      } else {
        masked_rows <- rep(TRUE, nrow(safe_df))
      }

      for (q in quasi_ids) {
        safe_df[[q]] <- as.character(safe_df[[q]])
        safe_df[[q]][masked_rows] <- mask_value
      }
      n_masked <- as.integer(sum(masked_rows))
    }
  }

  risk_after <- assess_reidentification_risk(
    data = safe_df,
    quasi_ids = quasi_ids,
    k_min = k_min,
    sensitive_col = sensitive_col,
    l_min = l_min,
    include_na = include_na
  )

  structure(
    list(
      data = safe_df,
      strategy = strategy,
      k_min = as.integer(k_min),
      l_min = if (is.null(sensitive_col)) NA_integer_ else as.integer(l_min),
      n_rows_before = as.integer(nrow(data)),
      n_rows_after = as.integer(nrow(safe_df)),
      n_rows_suppressed = n_suppressed,
      n_rows_masked = n_masked,
      risk_before = risk_before,
      risk_after = risk_after
    ),
    class = "airgap_k_anonymized"
  )
}

#' @export
print.airgap_k_anonymized <- function(x, ...) {
  cat("<airgap_k_anonymized> [strategy=", x$strategy, ", k_min=", x$k_min, "]\n", sep = "")
  cat("  Rows:            ", x$n_rows_before, " -> ", x$n_rows_after,
      " (suppressed=", x$n_rows_suppressed, ", masked=", x$n_rows_masked, ")\n", sep = "")
  cat("  k-anonymity:     ",
      if (isTRUE(x$risk_before$passes_k_anonymity)) "PASS" else "FAIL",
      " -> ",
      if (isTRUE(x$risk_after$passes_k_anonymity)) "PASS" else "FAIL",
      " (min_k: ", x$risk_before$min_k, " -> ", x$risk_after$min_k, ")\n", sep = "")
  cat("  Prosecutor max:  ",
      sprintf("%.4f -> %.4f", x$risk_before$prosecutor_risk_max, x$risk_after$prosecutor_risk_max),
      "\n", sep = "")
  invisible(x)
}
