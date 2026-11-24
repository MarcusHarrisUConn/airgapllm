# Pillar 5 (v0.3.0): Production Clinical & HPC Workflow Utilities

#' Safely Normalize Mixed Latin-1 / Windows-1252 / UTF-8 Text to Valid UTF-8
#'
#' Clinical exports from REDCap, Epic, Excel, or legacy SPSS/SAS CSV files
#' frequently contain Windows-1252 smart quotes (`0x91`-`0x94`), en/em-dashes
#' (`0x96`-`0x97`), or Latin-1 accented bytes that can trigger encoding errors in
#' downstream UTF-8 regex and JSON pipelines. Normalizes character vectors
#' cleanly into valid UTF-8 while preserving `NA_character_` entries.
#'
#' @param x Character vector.
#' @return Character vector guaranteed to contain valid UTF-8 strings (or `NA`).
#' @noRd
normalize_text_utf8 <- function(x) {
  if (!is.character(x) || length(x) == 0L) return(x)
  out <- x
  for (i in seq_along(out)) {
    s <- out[i]
    if (is.na(s) || !nzchar(s)) next
    if (identical(Encoding(s), "UTF-8") && isTRUE(validUTF8(s))) next
    # Try iconv from current/UTF-8 first if valid; otherwise fall back to Windows-1252 -> Latin-1 -> safe replacement
    if (isTRUE(validUTF8(s))) {
      out[i] <- enc2utf8(s)
      next
    }
    conv <- suppressWarnings(iconv(s, from = "CP1252", to = "UTF-8", sub = NA_character_))
    if (is.na(conv) || !isTRUE(validUTF8(conv))) {
      conv <- suppressWarnings(iconv(s, from = "latin1", to = "UTF-8", sub = ""))
    }
    if (is.na(conv) || !isTRUE(validUTF8(conv))) {
      conv <- suppressWarnings(iconv(s, from = "", to = "UTF-8", sub = ""))
    }
    out[i] <- enc2utf8(conv %||% "")
  }
  out
}

#' Deterministic Overlapping Chunker for Long Clinical Transcripts
#'
#' Splits long unstructured documents (such as therapy transcripts, qualitative
#' interviews, or multi-page clinical histories) that exceed local LLM context
#' windows into deterministic, overlapping chunks aligned on paragraph or
#' sentence boundaries while preserving `doc_id`, `chunk_index`, character
#' offsets, and unique `chunk_id` provenance for re-aggregation.
#'
#' @param data A data frame containing documents to chunk.
#' @param text_col Character scalar name of the text column in `data`.
#' @param id_col Optional character scalar column name supplying unique
#'   document IDs. If `NULL`, synthesizes `"1"`, `"2"`, ..., `"N"`.
#' @param max_chars Positive integer maximum character length per chunk
#'   (minimum `50L`, default `3000L`).
#' @param overlap_chars Non-negative integer character overlap carried from the
#'   end of each chunk into the start of the next chunk (must be strictly less
#'   than `max_chars`, default `250L`).
#' @param split_on Character scalar boundary preference: `"paragraph"`
#'   (default, prefers blank-line paragraph breaks before falling back to
#'   sentence/word breaks), `"sentence"`, or `"character"`.
#'
#' @return A `tibble` with columns `doc_id`, `chunk_id`, `chunk_index`,
#'   `n_chunks`, `start_char`, `end_char`, `char_count`, and `chunk_text`.
#'
#' @export
#' @examples
#' long_df <- tibble::tibble(
#'   doc_id = "T01",
#'   transcript = paste(
#'     rep("Patient described steady progress with sleep hygiene and mindfulness exercises.", 12),
#'     collapse = " "
#'   )
#' )
#' chunks <- chunk_clinical_texts(long_df, "transcript", id_col = "doc_id",
#'                                max_chars = 300L, overlap_chars = 60L)
#' chunks[, c("doc_id", "chunk_id", "chunk_index", "n_chunks", "char_count")]
chunk_clinical_texts <- function(
  data,
  text_col,
  id_col = NULL,
  max_chars = 3000L,
  overlap_chars = 250L,
  split_on = c("paragraph", "sentence", "character")
) {
  if (!is.data.frame(data)) {
    cli::cli_abort("{.arg data} must be a data frame or tibble.", class = "airgap_validation_error")
  }
  assert_scalar_string(text_col, "text_col")
  if (!text_col %in% names(data)) {
    cli::cli_abort("Column {.val {text_col}} not found in {.arg data}.", class = "airgap_validation_error")
  }
  split_on <- match.arg(split_on)

  max_chars <- assert_scalar_int(max_chars, "max_chars", min = 50L)
  overlap_chars <- assert_scalar_int(overlap_chars, "overlap_chars", min = 0L, max = max_chars - 1L)

  if (nrow(data) == 0L) {
    return(tibble::tibble(
      doc_id = character(),
      chunk_id = character(),
      chunk_index = integer(),
      n_chunks = integer(),
      start_char = integer(),
      end_char = integer(),
      char_count = integer(),
      chunk_text = character()
    ))
  }

  if (is.null(id_col)) {
    doc_ids <- as.character(seq_len(nrow(data)))
  } else {
    assert_scalar_string(id_col, "id_col")
    if (!id_col %in% names(data)) {
      cli::cli_abort("ID column {.val {id_col}} not found in {.arg data}.", class = "airgap_validation_error")
    }
    doc_ids <- as.character(data[[id_col]])
    if (any(is.na(doc_ids)) || any(!nzchar(doc_ids))) {
      cli::cli_abort("{.arg id_col} values must be non-NA and non-empty.", class = "airgap_validation_error")
    }
    if (anyDuplicated(doc_ids)) {
      cli::cli_abort("{.arg id_col} values must be unique.", class = "airgap_validation_error")
    }
  }

  texts <- normalize_text_utf8(as.character(data[[text_col]]))

  choose_cut <- function(txt, start_pos, limit_end, mode) {
    total_len <- nchar(txt, type = "chars")
    if (limit_end >= total_len) return(total_len)
    window <- substr(txt, start_pos, limit_end)
    win_len <- nchar(window, type = "chars")
    # Ensure every cut strictly advances past overlap_chars so chunks never nest into duplicates
    min_cut <- min(win_len, max(1L, as.integer(floor(win_len * 0.4)), overlap_chars + 1L))

    if (identical(mode, "paragraph")) {
      m <- gregexpr("\\n\\s*\\n", window, perl = TRUE)[[1L]]
      if (!(length(m) == 1L && m[1L] == -1L)) {
        ends_m <- as.integer(m) + as.integer(attr(m, "match.length")) - 1L
        good <- ends_m[ends_m >= min_cut]
        if (length(good) > 0L) return(start_pos + max(good) - 1L)
      }
    }

    if (mode %in% c("paragraph", "sentence")) {
      m <- gregexpr("[.!?][\"')\\]]*(?:\\s+|$)", window, perl = TRUE)[[1L]]
      if (!(length(m) == 1L && m[1L] == -1L)) {
        ends_m <- as.integer(m) + as.integer(attr(m, "match.length")) - 1L
        good <- ends_m[ends_m >= min_cut]
        if (length(good) > 0L) return(start_pos + max(good) - 1L)
      }
      # Fall back to whitespace word boundary so words aren't sliced mid-token
      m_ws <- gregexpr("\\s+", window, perl = TRUE)[[1L]]
      if (!(length(m_ws) == 1L && m_ws[1L] == -1L)) {
        ends_ws <- as.integer(m_ws) + as.integer(attr(m_ws, "match.length")) - 1L
        good_ws <- ends_ws[ends_ws >= min_cut]
        if (length(good_ws) > 0L) return(start_pos + max(good_ws) - 1L)
      }
    }

    limit_end
  }

  rows_out <- list()

  for (i in seq_along(doc_ids)) {
    did <- doc_ids[i]
    txt <- texts[i]

    if (is.na(txt) || !nzchar(txt)) {
      rows_out[[length(rows_out) + 1L]] <- list(
        doc_id = did,
        chunk_id = paste0(did, "_chunk_001"),
        chunk_index = 1L,
        n_chunks = 1L,
        start_char = if (is.na(txt)) NA_integer_ else 1L,
        end_char = if (is.na(txt)) NA_integer_ else 0L,
        char_count = if (is.na(txt)) NA_integer_ else 0L,
        chunk_text = txt
      )
      next
    }

    total_len <- nchar(txt, type = "chars")
    doc_chunks <- list()
    cur_start <- 1L

    while (cur_start <= total_len) {
      limit_end <- min(total_len, cur_start + max_chars - 1L)
      cut_end <- choose_cut(txt, cur_start, limit_end, split_on)
      if (cut_end < cur_start) cut_end <- limit_end

      piece <- substr(txt, cur_start, cut_end)
      doc_chunks[[length(doc_chunks) + 1L]] <- list(
        start_char = cur_start,
        end_char = cut_end,
        chunk_text = piece
      )

      if (cut_end >= total_len) break
      next_start <- max(cur_start + 1L, cut_end - overlap_chars + 1L)
      # Snap overlap start forward to a clean word boundary only for paragraph/sentence modes
      if (!identical(split_on, "character") && overlap_chars > 0L && next_start > cur_start + 1L && next_start < cut_end) {
        prefix_slice <- substr(txt, next_start, cut_end)
        ws_pos <- regexpr("\\s+\\S", prefix_slice, perl = TRUE)[1L]
        if (ws_pos > 1L && ws_pos <= min(40L, overlap_chars)) {
          # Move to first non-space char after the whitespace
          ws_len <- attr(regexpr("\\s+", substr(prefix_slice, ws_pos, nchar(prefix_slice)), perl = TRUE), "match.length")
          cand <- next_start + ws_pos + ws_len - 2L
          if (cand > cur_start && cand < cut_end) next_start <- cand
        }
      }
      cur_start <- next_start
    }

    n_ch <- length(doc_chunks)
    for (k in seq_len(n_ch)) {
      ch <- doc_chunks[[k]]
      rows_out[[length(rows_out) + 1L]] <- list(
        doc_id = did,
        chunk_id = sprintf("%s_chunk_%03d", did, k),
        chunk_index = as.integer(k),
        n_chunks = as.integer(n_ch),
        start_char = as.integer(ch$start_char),
        end_char = as.integer(ch$end_char),
        char_count = as.integer(nchar(ch$chunk_text, type = "chars")),
        chunk_text = ch$chunk_text
      )
    }
  }

  tibble::tibble(
    doc_id = vapply(rows_out, `[[`, character(1L), "doc_id"),
    chunk_id = vapply(rows_out, `[[`, character(1L), "chunk_id"),
    chunk_index = vapply(rows_out, `[[`, integer(1L), "chunk_index"),
    n_chunks = vapply(rows_out, `[[`, integer(1L), "n_chunks"),
    start_char = vapply(rows_out, `[[`, integer(1L), "start_char"),
    end_char = vapply(rows_out, `[[`, integer(1L), "end_char"),
    char_count = vapply(rows_out, `[[`, integer(1L), "char_count"),
    chunk_text = vapply(rows_out, `[[`, character(1L), "chunk_text")
  )
}

#' Pre-Inference Privacy Dry-Run Audit for Research Data Frames
#'
#' Performs a non-destructive pre-run PII inspection across a data frame text
#' column before calling [airgap_extract()]. Produces aggregate per-entity
#' counts, row coverage metrics, high-PII-density row flags, HIPAA Safe Harbor
#' advisories, Unicode obfuscation warnings, and strictly redacted preview
#' snippets containing **zero raw sensitive values**.
#'
#' @param data A data frame containing text rows to audit.
#' @param text_col Character scalar name of the text column in `data`.
#' @param config An [pii_config()] configuration object.
#' @param id_col Optional character scalar column name for row identifiers.
#' @param high_density_threshold Positive integer minimum entity count in a
#'   single row to flag as high-PII-density (default `3L`).
#' @param preview_n Non-negative integer number of redacted preview snippets to
#'   include (default `5L`).
#' @param preview_chars Positive integer maximum preview snippet length
#'   (default `120L`).
#'
#' @return An S3 object of class `"airgap_pii_audit"` containing `report`
#'   (`airgap_privacy_report`), `row_summary` (tibble), `high_density_rows`
#'   (character vector of row IDs), `obfuscated_rows` (integer count),
#'   `warnings` (character vector), and `masked_previews` (tibble with zero raw
#'   PII).
#'
#' @export
#' @examples
#' data("synthetic_notes", package = "airgapllm")
#' aud <- pii_audit_dataframe(synthetic_notes, "note_text", id_col = "note_id")
#' aud
pii_audit_dataframe <- function(
  data,
  text_col,
  config = pii_config(),
  id_col = NULL,
  high_density_threshold = 3L,
  preview_n = 5L,
  preview_chars = 120L
) {
  if (!is.data.frame(data)) {
    cli::cli_abort("{.arg data} must be a data frame or tibble.", class = "airgap_validation_error")
  }
  assert_scalar_string(text_col, "text_col")
  if (!text_col %in% names(data)) {
    cli::cli_abort("Column {.val {text_col}} not found in {.arg data}.", class = "airgap_validation_error")
  }
  if (!inherits(config, "airgap_pii_config")) {
    cli::cli_abort("{.arg config} must be an `airgap_pii_config` object.", class = "airgap_validation_error")
  }
  high_density_threshold <- assert_scalar_int(high_density_threshold, "high_density_threshold", min = 1L)
  preview_n <- assert_scalar_int(preview_n, "preview_n", min = 0L)
  preview_chars <- assert_scalar_int(preview_chars, "preview_chars", min = 20L)

  row_ids <- if (is.null(id_col)) {
    as.character(seq_len(nrow(data)))
  } else {
    assert_scalar_string(id_col, "id_col")
    if (!id_col %in% names(data)) {
      cli::cli_abort("ID column {.val {id_col}} not found in {.arg data}.", class = "airgap_validation_error")
    }
    as.character(data[[id_col]])
  }

  texts <- normalize_text_utf8(as.character(data[[text_col]]))
  stopwords <- pii_name_stopwords()
  n <- length(texts)

  doc_spans <- vector("list", n)
  n_ent <- integer(n)
  ent_labels <- character(n)
  obf_flags <- logical(n)
  redacted_all <- character(n)

  for (i in seq_len(n)) {
    txt <- texts[i]
    if (is.na(txt) || !nzchar(txt)) {
      doc_spans[[i]] <- list()
      n_ent[i] <- 0L
      ent_labels[i] <- ""
      obf_flags[i] <- FALSE
      redacted_all[i] <- if (is.na(txt)) NA_character_ else ""
      next
    }
    canon <- canonicalize_pii_text(txt)
    obf_flags[i] <- isTRUE(canon$had_obfuscation)
    spans <- detect_pii_single(txt, config = config, stopwords = stopwords)
    doc_spans[[i]] <- spans
    n_ent[i] <- length(spans)
    if (length(spans) > 0L) {
      types <- vapply(spans, `[[`, character(1L), "entity_type")
      ent_labels[i] <- paste(sort(unique(types)), collapse = ", ")
      repls <- paste0("[REDACTED_", toupper(types), "]")
      redacted_all[i] <- apply_span_replacements(txt, spans, repls)
    } else {
      ent_labels[i] <- ""
      redacted_all[i] <- txt
    }
  }

  report <- build_privacy_report_from_spans(n, doc_spans, config)
  is_high <- n_ent >= high_density_threshold
  high_ids <- row_ids[is_high]

  row_summary <- tibble::tibble(
    row_id = row_ids,
    n_entities = n_ent,
    entity_types = ent_labels,
    high_density = is_high
  )

  # Build strictly redacted previews prioritizing rows with PII detections
  prev_idx <- order(-n_ent, seq_len(n))
  prev_idx <- utils::head(prev_idx, min(preview_n, n))
  if (length(prev_idx) > 0L) {
    snips <- vapply(redacted_all[prev_idx], function(s) {
      if (is.na(s)) return("<NA>")
      clean <- gsub("\\s+", " ", trimws(s), perl = TRUE)
      if (nchar(clean, type = "chars") > preview_chars) {
        paste0(substr(clean, 1L, preview_chars - 3L), "...")
      } else {
        clean
      }
    }, character(1L), USE.NAMES = FALSE)
    masked_previews <- tibble::tibble(
      row_id = row_ids[prev_idx],
      n_entities = n_ent[prev_idx],
      redacted_preview = snips
    )
  } else {
    masked_previews <- tibble::tibble(
      row_id = character(),
      n_entities = integer(),
      redacted_preview = character()
    )
  }

  advisories <- character()
  if (length(high_ids) > 0L) {
    advisories <- c(
      advisories,
      paste0(
        length(high_ids), " row(s) exceed high-PII-density threshold (>= ",
        high_density_threshold, " entities/row); review custom_dictionary coverage before inference."
      )
    )
  }
  if (any(obf_flags)) {
    advisories <- c(
      advisories,
      paste0(
        sum(obf_flags), " row(s) contain Unicode obfuscators or non-ASCII typography (normalized automatically)."
      )
    )
  }
  if (nrow(report$by_entity) > 0L) {
    if ("age_over_89" %in% report$by_entity$entity_type) {
      cnt <- report$by_entity$count[report$by_entity$entity_type == "age_over_89"]
      advisories <- c(
        advisories,
        paste0("HIPAA Safe Harbor alert: ", cnt, " age > 89 reference(s) detected and scheduled for redaction.")
      )
    }
    if ("zip_code" %in% report$by_entity$entity_type) {
      cnt <- report$by_entity$count[report$by_entity$entity_type == "zip_code"]
      advisories <- c(
        advisories,
        paste0("HIPAA Safe Harbor alert: ", cnt, " geographic ZIP code / restricted 3-digit prefix span(s) detected.")
      )
    }
    if ("ssn" %in% report$by_entity$entity_type) {
      cnt <- report$by_entity$count[report$by_entity$entity_type == "ssn"]
      advisories <- c(
        advisories,
        paste0("High-sensitivity identifier alert: ", cnt, " SSN pattern(s) detected.")
      )
    }
  }

  structure(
    list(
      report = report,
      row_summary = row_summary,
      high_density_rows = high_ids,
      high_density_threshold = high_density_threshold,
      obfuscated_rows = as.integer(sum(obf_flags)),
      warnings = advisories,
      masked_previews = masked_previews
    ),
    class = "airgap_pii_audit"
  )
}

#' @export
print.airgap_pii_audit <- function(x, ...) {
  cat("<airgap_pii_audit> (pre-inference privacy dry-run; zero raw PII)\n")
  cat("  Rows scanned:        ", x$report$n_documents, "\n", sep = "")
  cat("  Rows with PII:       ", x$report$n_documents_with_pii, " (",
      x$report$pct_documents_with_pii, "%)\n", sep = "")
  cat("  Total PII spans:     ", x$report$total_entities, "\n", sep = "")
  cat("  High-density rows:   ", length(x$high_density_rows),
      " (>= ", x$high_density_threshold, " entities)\n", sep = "")
  cat("  Unicode-normalized:  ", x$obfuscated_rows, " row(s)\n", sep = "")
  if (nrow(x$report$by_entity) > 0L) {
    cat("  Entity breakdown:\n")
    for (i in seq_len(nrow(x$report$by_entity))) {
      r <- x$report$by_entity[i, , drop = FALSE]
      cat("    - ", r$entity_type, ": ", r$count, " (", r$n_documents, " rows, ", r$pct_documents, "%)\n", sep = "")
    }
  }
  if (length(x$warnings) > 0L) {
    cat("  Advisories:\n")
    for (w in x$warnings) {
      cat("    [!] ", w, "\n", sep = "")
    }
  }
  invisible(x)
}

#' Estimate GPU VRAM Requirements for Local Open-Weights LLM Deployment
#'
#' Estimates total GPU VRAM (in gigabytes) needed to serve a local open-weights
#' LLM under `Ollama`, `llama.cpp`, or `vLLM` as a function of model parameter
#' count (in billions), weight quantization (`Q4_K_M`, `Q6_K`, `Q8_0`, `FP16`),
#' context window length, concurrent batch size, and KV-cache precision, helping
#' research labs size lab workstations and HPC GPU requests cleanly before
#' launching air-gapped containers.
#'
#' @param params_b Positive numeric model parameter count in billions (e.g.,
#'   `8` for Llama-3.1-8B, `14` for Qwen-2.5-14B, `70` for Llama-3.1-70B).
#' @param quantization Character scalar weight quantization format:
#'   `"Q4_K_M"` (default), `"Q6_K"`, `"Q8_0"`, or `"FP16"`.
#' @param context_length Positive integer sequence context window in tokens
#'   (default `4096L`).
#' @param batch_size Positive integer number of concurrent requests / batch
#'   sequences held in KV cache (default `1L`).
#' @param n_layers Optional positive integer transformer layer count. When
#'   `NULL` (default), inferred from typical GQA open-weights architectures
#'   scaled by `params_b`.
#' @param kv_cache_quant Character scalar KV-cache precision: `"FP16"`
#'   (default), `"Q8_0"`, or `"Q4_0"`.
#' @param overhead_gb Non-negative numeric framework/CUDA/activation memory
#'   overhead in GB (default `1.2`).
#'
#' @return An S3 object of class `"airgap_vram_estimate"` with `params_b`,
#'   `quantization`, `context_length`, `batch_size`, `kv_cache_quant`,
#'   `weights_gb`, `kv_cache_gb`, `overhead_gb`, `total_vram_gb`,
#'   `recommended_gpu_tier`, and `fits_tiers` (tibble).
#'
#' @export
#' @examples
#' estimate_vram_requirements(8, quantization = "Q4_K_M", context_length = 8192L)
#' estimate_vram_requirements(70, quantization = "Q4_K_M", context_length = 4096L, batch_size = 4L)
estimate_vram_requirements <- function(
  params_b,
  quantization = c("Q4_K_M", "Q6_K", "Q8_0", "FP16"),
  context_length = 4096L,
  batch_size = 1L,
  n_layers = NULL,
  kv_cache_quant = c("FP16", "Q8_0", "Q4_0"),
  overhead_gb = 1.2
) {
  if (!is.numeric(params_b) || length(params_b) != 1L || is.na(params_b) || !is.finite(params_b) || params_b <= 0) {
    cli::cli_abort("{.arg params_b} must be a positive finite number (billions of parameters).", class = "airgap_validation_error")
  }
  quantization <- match.arg(quantization)
  kv_cache_quant <- match.arg(kv_cache_quant)

  context_length <- assert_scalar_int(context_length, "context_length", min = 128L)
  batch_size <- assert_scalar_int(batch_size, "batch_size", min = 1L)

  if (!is.numeric(overhead_gb) || length(overhead_gb) != 1L || is.na(overhead_gb) || !is.finite(overhead_gb) || overhead_gb < 0) {
    cli::cli_abort("{.arg overhead_gb} must be a non-negative finite number.", class = "airgap_validation_error")
  }

  # Effective bytes per parameter including block scale metadata
  bytes_per_param <- switch(
    quantization,
    "Q4_K_M" = 0.60,
    "Q6_K"   = 0.82,
    "Q8_0"   = 1.07,
    "FP16"   = 2.00
  )
  kv_bytes <- switch(
    kv_cache_quant,
    "FP16" = 2.0,
    "Q8_0" = 1.05,
    "Q4_0" = 0.55
  )

  # Typical GQA transformer layer & KV hidden dimensions (Llama 3 / Qwen 2.5 / Mistral class)
  arch <- if (params_b <= 4) {
    list(layers = 28L, kv_heads = 8L, head_dim = 128L)
  } else if (params_b <= 10) {
    list(layers = 32L, kv_heads = 8L, head_dim = 128L)
  } else if (params_b <= 20) {
    list(layers = 40L, kv_heads = 8L, head_dim = 128L)
  } else if (params_b <= 40) {
    list(layers = 64L, kv_heads = 8L, head_dim = 128L)
  } else {
    list(layers = 80L, kv_heads = 8L, head_dim = 128L)
  }

  if (!is.null(n_layers)) {
    arch$layers <- assert_scalar_int(n_layers, "n_layers", min = 1L)
  }

  # Weights GB (GiB = 1024^3 bytes; params_b * 1e9 * bytes_per_param / 1024^3)
  weights_gb <- (params_b * 1e9 * bytes_per_param) / (1024^3)

  # KV cache bytes: 2 (K + V) * n_layers * kv_heads * head_dim * context_length * batch_size * kv_bytes
  kv_cache_bytes <- 2 * arch$layers * arch$kv_heads * arch$head_dim *
    as.numeric(context_length) * as.numeric(batch_size) * kv_bytes
  kv_cache_gb <- kv_cache_bytes / (1024^3)

  # Add mild activation scaling with batch_size
  eff_overhead_gb <- overhead_gb + 0.15 * max(0, batch_size - 1L)
  total_gb <- weights_gb + kv_cache_gb + eff_overhead_gb

  tiers <- tibble::tibble(
    gpu_tier = c(
      "8 GB (Workstation RTX 4060 / 16 GB Unified)",
      "16 GB (RTX 4080 / A4000 / V100-16GB)",
      "24 GB (RTX 3090/4090 / A10G / L4)",
      "40 GB (A100-40GB)",
      "48 GB (L40S / A6000)",
      "80 GB (A100-80GB / H100-80GB)",
      "160 GB (2x A100/H100 80GB)"
    ),
    vram_gb = c(8, 16, 24, 40, 48, 80, 160),
    fits = total_gb <= c(8, 16, 24, 40, 48, 80, 160),
    headroom_gb = round(c(8, 16, 24, 40, 48, 80, 160) - total_gb, 2)
  )

  fit_idx <- which(tiers$fits)
  rec_tier <- if (length(fit_idx) > 0L) {
    tiers$gpu_tier[fit_idx[1L]]
  } else {
    "Multi-GPU (> 160 GB total VRAM; tensor-parallel vLLM required)"
  }

  structure(
    list(
      params_b = as.numeric(params_b),
      quantization = quantization,
      context_length = context_length,
      batch_size = batch_size,
      n_layers = arch$layers,
      kv_cache_quant = kv_cache_quant,
      weights_gb = round(weights_gb, 2),
      kv_cache_gb = round(kv_cache_gb, 2),
      overhead_gb = round(eff_overhead_gb, 2),
      total_vram_gb = round(total_gb, 2),
      recommended_gpu_tier = rec_tier,
      fits_tiers = tiers
    ),
    class = "airgap_vram_estimate"
  )
}

#' @export
print.airgap_vram_estimate <- function(x, ...) {
  cat("<airgap_vram_estimate>\n")
  cat("  Model:            ", x$params_b, "B parameters (", x$quantization, ", ",
      x$n_layers, " layers)\n", sep = "")
  cat("  Context / Batch:  ", x$context_length, " tokens x ", x$batch_size,
      " (KV: ", x$kv_cache_quant, ")\n", sep = "")
  cat("  Weights VRAM:     ", sprintf("%.2f GB", x$weights_gb), "\n", sep = "")
  cat("  KV-Cache VRAM:    ", sprintf("%.2f GB", x$kv_cache_gb), "\n", sep = "")
  cat("  Runtime Overhead: ", sprintf("%.2f GB", x$overhead_gb), "\n", sep = "")
  cat("  Total Estimated:  ", sprintf("%.2f GB", x$total_vram_gb), "\n", sep = "")
  cat("  Recommended Tier: ", x$recommended_gpu_tier, "\n", sep = "")
  invisible(x)
}

#' Export a Self-Contained, Strictly PII-Free IRB / HIPAA Compliance Packet
#'
#' Assembles a self-contained audit directory suitable for attachment to an IRB
#' protocol submission, HIPAA Security Officer review, or reproducible
#' publication supplement. The packet includes a verified hash-chained JSONL
#' audit log, pre-flight isolation attestation JSON, hardened container
#' configurations (`docker run`, Compose YAML, Apptainer `.def`) when a pinned
#' `container_spec` is supplied, ready-to-paste Markdown and Quarto IRB
#' narratives, and a SHA-256 `packet_manifest.json`. Every file written to the
#' packet is scanned for accidental raw PII before sealing.
#'
#' @param out_dir Character scalar destination directory path for the
#'   compliance packet.
#' @param extraction Optional `airgap_extraction` or `airgap_consensus` result
#'   from [airgap_extract()] or [airgap_extract_consensus()].
#' @param audit_log_path Optional path to an existing hash-chained JSONL audit
#'   log (verified via [audit_log_verify()] prior to inclusion).
#' @param container_spec Optional [airgap_container_spec()] object. If pinned
#'   with `image_digest`, emits `container_docker_run.sh`,
#'   `docker-compose.yml`, and `container_apptainer.def` into the packet.
#' @param preflight Optional `airgap_preflight` record (defaults to
#'   `extraction_preflight(extraction)` when `extraction` is provided).
#' @param study_title Optional character scalar study title.
#' @param protocol_id Optional character scalar IRB protocol ID.
#' @param institution Optional character scalar institutional name.
#' @param pi_name Optional character scalar Principal Investigator name (for
#'   protocol header; omitted when `NULL`).
#' @param regulatory_framework Character vector subset of
#'   `c("HIPAA", "IRB", "FERPA")`.
#' @param overwrite Logical scalar; if `FALSE` (default), refuses to overwrite
#'   a non-empty `out_dir`.
#'
#' @return An S3 object of class `"airgap_compliance_packet"` containing
#'   `out_dir`, `files` (tibble of relative paths, sizes, and SHA-256 digests),
#'   `packet_digest`, `audit_valid`, `audit_chain_head`, and `created_at`.
#'
#' @export
#' @examples
#' df <- tibble::tibble(id = c("N1", "N2"), txt = c("Dr. Jane Doe visited.", "Mood stable."))
#' sc <- extraction_schema(mood = schema_field("enum", values = c("calm", "anxious")))
#' res <- airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id")
#' pkt_dir <- file.path(tempdir(), "demo_irb_packet")
#' pkt <- export_irb_compliance_packet(
#'   pkt_dir,
#'   extraction = res,
#'   protocol_id = "IRB-2026-0412",
#'   overwrite = TRUE
#' )
#' pkt
#' unlink(pkt_dir, recursive = TRUE)
export_irb_compliance_packet <- function(
  out_dir,
  extraction = NULL,
  audit_log_path = NULL,
  container_spec = NULL,
  preflight = NULL,
  study_title = NULL,
  protocol_id = NULL,
  institution = NULL,
  pi_name = NULL,
  regulatory_framework = c("HIPAA", "IRB"),
  overwrite = FALSE
) {
  assert_safe_host_path(out_dir, "out_dir", forbid_colon = FALSE)
  assert_safe_write_target(out_dir, arg = "out_dir")
  assert_scalar_logical(overwrite, "overwrite")

  if (is.null(extraction) && is.null(audit_log_path)) {
    cli::cli_abort(
      "Provide at least one of {.arg extraction} or {.arg audit_log_path}.",
      class = "airgap_validation_error"
    )
  }
  if (!is.null(extraction) && !inherits(extraction, c("airgap_extraction", "airgap_consensus"))) {
    cli::cli_abort(
      "{.arg extraction} must be an `airgap_extraction` or `airgap_consensus` object.",
      class = "airgap_validation_error"
    )
  }
  if (!is.null(container_spec) && !inherits(container_spec, "airgap_container_spec")) {
    cli::cli_abort("{.arg container_spec} must be an `airgap_container_spec` object.", class = "airgap_validation_error")
  }
  if (!is.null(preflight) && !inherits(preflight, "airgap_preflight")) {
    cli::cli_abort("{.arg preflight} must be an `airgap_preflight` object.", class = "airgap_validation_error")
  }

  # Pre-validate & scan protocol header strings before writing any packet files
  full_scan_cfg <- pii_config(detect_unlabeled_names = FALSE)
  pi_non_name_ents <- setdiff(pii_default_entities(), "person_name")
  pi_scan_cfg <- pii_config(entities = pi_non_name_ents, detect_unlabeled_names = FALSE)

  hdr_fields <- list(study_title = study_title, protocol_id = protocol_id, institution = institution)
  for (hnm in names(hdr_fields)) {
    hv <- hdr_fields[[hnm]]
    if (!is.null(hv)) {
      assert_scalar_string(hv, hnm)
      det_h <- pii_detect(hv, config = full_scan_cfg, include_values = FALSE)
      if (nrow(det_h) > 0L) {
        cli::cli_abort(
          "Compliance packet privacy guard tripped on {.arg {hnm}}: direct PII detected ({paste(unique(det_h$entity_type), collapse = ', ')}).",
          class = "airgap_audit_privacy_error"
        )
      }
    }
  }
  if (!is.null(pi_name)) {
    assert_scalar_string(pi_name, "pi_name")
    det_pi <- pii_detect(pi_name, config = pi_scan_cfg, include_values = FALSE)
    if (nrow(det_pi) > 0L) {
      cli::cli_abort(
        "Compliance packet privacy guard tripped on {.arg pi_name}: direct non-name PII detected ({paste(unique(det_pi$entity_type), collapse = ', ')}).",
        class = "airgap_audit_privacy_error"
      )
    }
  }

  dir_existed <- dir.exists(out_dir)
  if (dir_existed) {
    existing <- list.files(out_dir, all.files = FALSE)
    if (length(existing) > 0L && !isTRUE(overwrite)) {
      cli::cli_abort(
        "Output directory {.path {out_dir}} already exists and is non-empty; pass `overwrite = TRUE` to replace.",
        class = "airgap_validation_error"
      )
    }
  } else {
    dir.create(out_dir, recursive = TRUE, showWarnings = FALSE)
  }

  written_files <- character()

  # 1. Verified hash-chained audit log
  dest_audit <- file.path(out_dir, "audit_log.jsonl")
  assert_safe_write_target(dest_audit, arg = "audit_log.jsonl")
  if (!is.null(audit_log_path)) {
    ver_in <- audit_log_verify(audit_log_path, strict = TRUE)
    if (!isTRUE(ver_in$valid)) {
      cli::cli_abort(
        c(
          "Cannot export compliance packet from tampered or invalid audit log {.path {audit_log_path}}.",
          stats::setNames(escape_cli_braces(ver_in$issues), rep("x", length(ver_in$issues)))
        ),
        class = "airgap_audit_tamper_error"
      )
    }
    file.copy(audit_log_path, dest_audit, overwrite = TRUE)
  } else {
    if (file.exists(dest_audit)) unlink(dest_audit)
    ev_type <- if (inherits(extraction, "airgap_consensus")) "consensus_extraction_run" else "extraction_run"
    audit_log_append(dest_audit, extraction, event_type = ev_type)
  }
  ver_dest <- audit_log_verify(dest_audit, strict = TRUE)
  if (!isTRUE(ver_dest$valid)) {
    cli::cli_abort("Internal error: exported audit log failed verification.", class = "airgap_audit_tamper_error")
  }
  written_files <- c(written_files, "audit_log.jsonl")

  # 2. Pre-flight isolation attestation JSON (zero raw text)
  eff_pf <- preflight %||% (if (!is.null(extraction)) extraction_preflight(extraction) else NULL)
  if (!is.null(eff_pf)) {
    dest_pf <- file.path(out_dir, "preflight_attestation.json")
    assert_safe_write_target(dest_pf, arg = "preflight_attestation.json")
    pf_payload <- list(
      status = eff_pf$status,
      passed = eff_pf$passed,
      spec_digest = eff_pf$spec_digest,
      model_digest = eff_pf$model_digest,
      endpoint_class = eff_pf$endpoint_class,
      checked_at = eff_pf$checked_at,
      record_hash = eff_pf$record_hash,
      signature = eff_pf$signature,
      checks = lapply(seq_len(nrow(eff_pf$checks)), function(i) as.list(eff_pf$checks[i, , drop = FALSE]))
    )
    writeLines(
      as.character(jsonlite::toJSON(pf_payload, auto_unbox = TRUE, pretty = TRUE, null = "null")),
      con = dest_pf,
      useBytes = TRUE
    )
    written_files <- c(written_files, "preflight_attestation.json")
  }

  # 3. Hardened container specs (when pinned)
  if (!is.null(container_spec)) {
    if (!is.null(container_spec$image_digest)) {
      dest_run <- file.path(out_dir, "container_docker_run.sh")
      dest_cmp <- file.path(out_dir, "docker-compose.yml")
      dest_app <- file.path(out_dir, "container_apptainer.def")
      assert_safe_write_target(dest_run, arg = "container_docker_run.sh")
      assert_safe_write_target(dest_cmp, arg = "docker-compose.yml")
      assert_safe_write_target(dest_app, arg = "container_apptainer.def")
      emit_docker_run(container_spec, file = dest_run)
      emit_docker_compose(container_spec, file = dest_cmp)
      emit_apptainer_def(container_spec, file = dest_app)
      written_files <- c(
        written_files,
        "container_docker_run.sh",
        "docker-compose.yml",
        "container_apptainer.def"
      )
    } else {
      cli::cli_warn("Skipping container emitters in compliance packet because `container_spec$image_digest` is unpinned.")
    }
  }

  # 4. Ready-to-paste Markdown & Quarto IRB narratives (verified from dest_audit)
  dest_md <- file.path(out_dir, "irb_protocol_narrative.md")
  dest_qmd <- file.path(out_dir, "irb_protocol_narrative.qmd")
  assert_safe_write_target(dest_md, arg = "irb_protocol_narrative.md")
  assert_safe_write_target(dest_qmd, arg = "irb_protocol_narrative.qmd")
  generate_irb_narrative(
    source = dest_audit,
    study_title = study_title,
    protocol_id = protocol_id,
    institution = institution,
    pi_name = pi_name,
    regulatory_framework = regulatory_framework,
    format = "markdown",
    file = dest_md
  )
  generate_irb_narrative(
    source = dest_audit,
    study_title = study_title,
    protocol_id = protocol_id,
    institution = institution,
    pi_name = pi_name,
    regulatory_framework = regulatory_framework,
    format = "quarto",
    file = dest_qmd
  )
  written_files <- c(written_files, "irb_protocol_narrative.md", "irb_protocol_narrative.qmd")

  # 5. Active zero-PII verification scan across EVERY exported artifact before sealing
  strip_safe_protocol_tokens <- function(txt, allow_pi_line = FALSE) {
    if (isTRUE(allow_pi_line) && !is.null(pi_name)) {
      lines <- strsplit(txt, "\n", fixed = TRUE)[[1L]]
      lines <- lines[!grepl("^- \\*\\*Principal Investigator:\\*\\* ", lines)]
      txt <- paste(lines, collapse = "\n")
    }
    # Strip canonical ISO-8601 UTC timestamps and loopback literals so they do not false-positive
    txt <- gsub("\\b\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z\\b", "[TS_UTC]", txt, perl = TRUE)
    txt <- gsub("\\b(?:127\\.0\\.0\\.1|0\\.0\\.0\\.0)\\b", "[LOOPBACK_IP]", txt, perl = TRUE)
    txt <- gsub("\\[::1\\]|(?<![0-9a-fA-F:])::1(?![0-9a-fA-F:])", "[LOOPBACK_IP6]", txt, perl = TRUE)
    txt
  }

  for (fn in written_files) {
    txt_blob <- paste(readLines(file.path(out_dir, fn), warn = FALSE, encoding = "UTF-8"), collapse = "\n")
    is_narr <- fn %in% c("irb_protocol_narrative.md", "irb_protocol_narrative.qmd")
    scrubbed <- strip_safe_protocol_tokens(txt_blob, allow_pi_line = is_narr)
    det <- pii_detect(scrubbed, config = full_scan_cfg, include_values = FALSE)
    if (nrow(det) > 0L) {
      unlink(file.path(out_dir, written_files), force = TRUE)
      cli::cli_abort(
        "Compliance packet privacy guard tripped on {.file {fn}}: direct PII detected ({paste(unique(det$entity_type), collapse = ', ')}).",
        class = "airgap_audit_privacy_error"
      )
    }
  }

  # 6. Compute per-file SHA-256 manifest, scan manifest body itself, and seal packet_manifest.json
  written_files <- sort(unique(written_files))
  full_paths <- file.path(out_dir, written_files)
  file_digests <- vapply(full_paths, sha256_file_stream, character(1L))
  file_sizes <- as.numeric(file.info(full_paths)$size)

  files_tbl <- tibble::tibble(
    file = written_files,
    size_bytes = file_sizes,
    sha256 = unname(file_digests)
  )

  created_at <- utc_timestamp()
  manifest_body <- list(
    packet_version = "1.0",
    package_version = airgapllm_version(),
    created_at = created_at,
    protocol_id = protocol_id,
    regulatory_framework = as.list(regulatory_framework),
    audit_valid = isTRUE(ver_dest$valid),
    audit_entries = ver_dest$n_entries,
    audit_chain_head = ver_dest$chain_head_hash,
    zero_pii_verified = TRUE,
    files = lapply(seq_len(nrow(files_tbl)), function(i) {
      list(
        file = files_tbl$file[i],
        size_bytes = files_tbl$size_bytes[i],
        sha256 = files_tbl$sha256[i]
      )
    })
  )
  packet_digest <- sha256_object(manifest_body)
  manifest_body$packet_digest <- packet_digest

  manifest_json <- as.character(jsonlite::toJSON(manifest_body, auto_unbox = TRUE, pretty = TRUE, null = "null"))
  det_man <- pii_detect(strip_safe_protocol_tokens(manifest_json), config = full_scan_cfg, include_values = FALSE)
  if (nrow(det_man) > 0L) {
    unlink(file.path(out_dir, written_files), force = TRUE)
    cli::cli_abort(
      "Compliance packet privacy guard tripped on {.file packet_manifest.json}: direct PII detected ({paste(unique(det_man$entity_type), collapse = ', ')}).",
      class = "airgap_audit_privacy_error"
    )
  }

  dest_manifest <- file.path(out_dir, "packet_manifest.json")
  assert_safe_write_target(dest_manifest, arg = "packet_manifest.json")
  writeLines(manifest_json, con = dest_manifest, useBytes = TRUE)

  structure(
    list(
      out_dir = normalizePath(out_dir, winslash = "/", mustWork = TRUE),
      files = files_tbl,
      packet_digest = packet_digest,
      audit_valid = isTRUE(ver_dest$valid),
      audit_chain_head = ver_dest$chain_head_hash,
      created_at = created_at
    ),
    class = "airgap_compliance_packet"
  )
}

#' @export
print.airgap_compliance_packet <- function(x, ...) {
  cat("<airgap_compliance_packet> [AUDIT: ", if (isTRUE(x$audit_valid)) "VERIFIED" else "INVALID", "]\n", sep = "")
  cat("  Directory:     ", x$out_dir, "\n", sep = "")
  cat("  Artifacts:     ", nrow(x$files), " file(s) + packet_manifest.json\n", sep = "")
  cat("  Audit head:    ", x$audit_chain_head, "\n", sep = "")
  cat("  Packet digest: ", x$packet_digest, "\n", sep = "")
  invisible(x)
}
