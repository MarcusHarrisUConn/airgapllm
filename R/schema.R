# Pillar 3a: Strict Typed Extraction Schema & Repair Validation

#' Define a Strictly Typed Field in an Extraction Schema
#'
#' Creates a field specification for use inside [extraction_schema()]. Enforces
#' strict scalar typing (`character`, `integer`, `numeric`, `logical`, `enum`),
#' explicit nullability, numeric bounds, string length bounds, and PCRE regex
#' patterns.
#'
#' @param type Character scalar field type: `"character"`, `"integer"`,
#'   `"numeric"`, `"logical"`, or `"enum"`.
#' @param description Character scalar human-readable instructions for the LLM.
#' @param nullable Logical scalar; whether JSON `null` (`NA` in R) is permitted.
#'   Defaults to `FALSE`.
#' @param values Character vector of allowed levels (required when
#'   `type = "enum"`).
#' @param min Optional numeric minimum bound (valid for `"integer"` and
#'   `"numeric"`).
#' @param max Optional numeric maximum bound (valid for `"integer"` and
#'   `"numeric"`).
#' @param pattern Optional PCRE regular expression constraint (valid for
#'   `"character"`).
#' @param min_length Optional non-negative integer minimum string length (valid
#'   for `"character"`).
#' @param max_length Optional positive integer maximum string length (valid for
#'   `"character"`).
#'
#' @return An S3 object of class `"airgap_schema_field"`.
#'
#' @export
#' @examples
#' schema_field("enum", values = c("low", "moderate", "high"), description = "Risk tier")
#' schema_field("integer", min = 0L, max = 10L, description = "Severity rating")
schema_field <- function(
  type = c("character", "integer", "numeric", "logical", "enum"),
  description = "",
  nullable = FALSE,
  values = NULL,
  min = NULL,
  max = NULL,
  pattern = NULL,
  min_length = NULL,
  max_length = NULL
) {
  type <- match.arg(type)
  assert_scalar_string(description, "description", allow_empty = TRUE)
  assert_scalar_logical(nullable, "nullable")

  if (identical(type, "enum")) {
    if (!is.character(values) || length(values) == 0L || any(is.na(values)) || any(!nzchar(values))) {
      cli::cli_abort("`enum` fields require a non-empty character vector in {.arg values}.", class = "airgap_validation_error")
    }
    values <- unique(values)
  } else if (!is.null(values)) {
    cli::cli_abort("{.arg values} is only valid when `type = 'enum'`.", class = "airgap_validation_error")
  }

  if (!is.null(min) || !is.null(max)) {
    if (!type %in% c("integer", "numeric")) {
      cli::cli_abort("{.arg min} and {.arg max} are only valid for `integer` or `numeric` fields.", class = "airgap_validation_error")
    }
    if (!is.null(min) && (!is.numeric(min) || length(min) != 1L || is.na(min) || !is.finite(min))) {
      cli::cli_abort("{.arg min} must be a finite numeric scalar.", class = "airgap_validation_error")
    }
    if (!is.null(max) && (!is.numeric(max) || length(max) != 1L || is.na(max) || !is.finite(max))) {
      cli::cli_abort("{.arg max} must be a finite numeric scalar.", class = "airgap_validation_error")
    }
    if (!is.null(min) && !is.null(max) && min > max) {
      cli::cli_abort("{.arg min} ({min}) cannot exceed {.arg max} ({max}).", class = "airgap_validation_error")
    }
  }

  if (!is.null(pattern)) {
    if (!identical(type, "character")) {
      cli::cli_abort("{.arg pattern} is only valid for `character` fields.", class = "airgap_validation_error")
    }
    assert_scalar_string(pattern, "pattern")
    tryCatch(
      suppressWarnings(grepl(pattern, "", perl = TRUE)),
      error = function(e) {
        cli::cli_abort("Invalid PCRE regex in {.arg pattern}: {conditionMessage(e)}", class = "airgap_validation_error")
      }
    )
  }

  if (!is.null(min_length) || !is.null(max_length)) {
    if (!identical(type, "character")) {
      cli::cli_abort("{.arg min_length} and {.arg max_length} are only valid for `character` fields.", class = "airgap_validation_error")
    }
    if (!is.null(min_length)) {
      min_length <- assert_scalar_int(min_length, "min_length", min = 0L)
    }
    if (!is.null(max_length)) {
      max_length <- assert_scalar_int(max_length, "max_length", min = 1L)
    }
    if (!is.null(min_length) && !is.null(max_length) && min_length > max_length) {
      cli::cli_abort("{.arg min_length} cannot exceed {.arg max_length}.", class = "airgap_validation_error")
    }
  }

  structure(
    list(
      type = type,
      description = description,
      nullable = nullable,
      values = values,
      min = min,
      max = max,
      pattern = pattern,
      min_length = min_length,
      max_length = max_length
    ),
    class = "airgap_schema_field"
  )
}

#' Define a Strict Structured Extraction Schema
#'
#' Declares the typed output schema for [airgap_extract()]. Each named argument
#' must be a [schema_field()] object. Computes a deterministic canonical
#' `schema_digest` used for checkpoint compatibility and audit trails.
#'
#' @param ... Named [schema_field()] objects (or a single named list of
#'   `airgap_schema_field` objects).
#' @param name Character scalar schema identifier. Defaults to `"extraction"`.
#' @param description Optional character scalar description of the extraction
#'   task.
#' @param strict_keys Logical scalar; if `TRUE` (default), rejects JSON outputs
#'   containing unexpected extra keys not declared in the schema.
#'
#' @return An S3 object of class `"airgap_schema"`.
#'
#' @export
#' @examples
#' sc <- extraction_schema(
#'   sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
#'   severity = schema_field("integer", min = 0L, max = 10L),
#'   crisis_flag = schema_field("logical"),
#'   summary = schema_field("character", max_length = 200L)
#' )
#' print(sc)
extraction_schema <- function(
  ...,
  name = "extraction",
  description = "",
  strict_keys = TRUE
) {
  assert_scalar_string(name, "name")
  assert_scalar_string(description, "description", allow_empty = TRUE)
  assert_scalar_logical(strict_keys, "strict_keys")

  dots <- list(...)
  if (length(dots) == 1L && is.null(names(dots)) && is.list(dots[[1L]]) && !inherits(dots[[1L]], "airgap_schema_field")) {
    fields <- dots[[1L]]
  } else {
    fields <- dots
  }

  if (length(fields) == 0L) {
    cli::cli_abort("At least one named `schema_field()` must be provided.", class = "airgap_validation_error")
  }
  nms <- names(fields)
  if (is.null(nms) || any(is.na(nms)) || any(!nzchar(trimws(nms)))) {
    cli::cli_abort("All fields in `extraction_schema()` must have non-empty names.", class = "airgap_validation_error")
  }
  if (anyDuplicated(nms)) {
    cli::cli_abort("Duplicate field names are not permitted in `extraction_schema()`.", class = "airgap_validation_error")
  }
  reserved <- c(".row_id", ".status", ".attempts", ".error", ".elapsed_ms")
  bad_res <- intersect(nms, reserved)
  if (length(bad_res) > 0L) {
    cli::cli_abort(
      "Field name(s) conflict with reserved metadata columns: {paste(bad_res, collapse = ', ')}.",
      class = "airgap_validation_error"
    )
  }
  for (nm in nms) {
    if (!inherits(fields[[nm]], "airgap_schema_field")) {
      cli::cli_abort(
        "Field {.val {nm}} must be constructed with `schema_field()`.",
        class = "airgap_validation_error"
      )
    }
  }

  core <- list(
    name = name,
    description = description,
    strict_keys = strict_keys,
    fields = fields
  )
  core$schema_digest <- sha256_object(core)
  structure(core, class = "airgap_schema")
}

#' @export
print.airgap_schema <- function(x, ...) {
  cat("<airgap_schema> '", x$name, "' (", length(x$fields), " fields, strict_keys=", x$strict_keys, ")\n", sep = "")
  for (nm in names(x$fields)) {
    f <- x$fields[[nm]]
    extra <- character()
    if (identical(f$type, "enum")) extra <- c(extra, paste0("values=[", paste(f$values, collapse = ","), "]"))
    if (!is.null(f$min)) extra <- c(extra, paste0("min=", f$min))
    if (!is.null(f$max)) extra <- c(extra, paste0("max=", f$max))
    if (!is.null(f$min_length)) extra <- c(extra, paste0("min_len=", f$min_length))
    if (!is.null(f$max_length)) extra <- c(extra, paste0("max_len=", f$max_length))
    if (!is.null(f$pattern)) extra <- c(extra, paste0("pattern=/", f$pattern, "/"))
    if (isTRUE(f$nullable)) extra <- c(extra, "nullable")
    suffix <- if (length(extra) > 0L) paste0(" (", paste(extra, collapse = ", "), ")") else ""
    cat("  - ", nm, ": ", f$type, suffix, "\n", sep = "")
  }
  cat("  Schema digest: ", x$schema_digest, "\n", sep = "")
  invisible(x)
}

#' Convert an `airgap_schema` to a Standard JSON Schema Object
#'
#' Produces a JSON Schema list representation compatible with Ollama structured
#' output (`format`) and OpenAI-compatible local endpoints (`response_format`).
#'
#' @param schema An [extraction_schema()] object.
#'
#' @return A named list representing the JSON Schema.
#'
#' @export
#' @examples
#' sc <- extraction_schema(score = schema_field("integer", min = 1L, max = 5L))
#' as_json_schema(sc)
as_json_schema <- function(schema) {
  if (!inherits(schema, "airgap_schema")) {
    cli::cli_abort("{.arg schema} must be an `airgap_schema` object.", class = "airgap_validation_error")
  }

  props <- list()
  for (nm in names(schema$fields)) {
    f <- schema$fields[[nm]]
    json_type <- switch(
      f$type,
      "character" = "string",
      "enum" = "string",
      "integer" = "integer",
      "numeric" = "number",
      "logical" = "boolean"
    )
    prop <- list(
      type = if (isTRUE(f$nullable)) list(json_type, "null") else json_type
    )
    if (nzchar(f$description)) prop$description <- f$description
    if (identical(f$type, "enum")) {
      prop$enum <- if (isTRUE(f$nullable)) c(as.list(f$values), list(NULL)) else as.list(f$values)
    }
    if (!is.null(f$min)) prop$minimum <- f$min
    if (!is.null(f$max)) prop$maximum <- f$max
    if (!is.null(f$min_length)) prop$minLength <- f$min_length
    if (!is.null(f$max_length)) prop$maxLength <- f$max_length
    if (!is.null(f$pattern)) prop$pattern <- f$pattern
    props[[nm]] <- prop
  }

  out <- list(
    type = "object",
    title = schema$name,
    properties = props,
    required = as.list(names(schema$fields)),
    additionalProperties = !isTRUE(schema$strict_keys)
  )
  if (nzchar(schema$description)) {
    out$description <- schema$description
  }
  out
}

#' Typed NA scalar for a schema field
#' @noRd
typed_na_for_field <- function(field) {
  switch(
    field$type,
    "character" = NA_character_,
    "enum" = NA_character_,
    "integer" = NA_integer_,
    "numeric" = NA_real_,
    "logical" = NA
  )
}

#' Extract clean JSON string from raw model response (supporting markdown fences)
#' @noRd
extract_json_payload <- function(raw_output) {
  if (!is.character(raw_output) || length(raw_output) != 1L || is.na(raw_output)) {
    return(NULL)
  }
  txt <- trimws(raw_output)
  if (!nzchar(txt)) return(NULL)

  # Strip single markdown ```json ... ``` fence if wrapping the response
  fence_match <- regexec("^```(?:json|JSON)?\\s*\\n([\\s\\S]*?)\\n```$", txt, perl = TRUE)
  m <- regmatches(txt, fence_match)[[1L]]
  if (length(m) >= 2L) {
    txt <- trimws(m[2L])
  }
  txt
}

#' Validate a Raw Model Output Against an `airgap_schema`
#'
#' Parses a raw JSON string (or named list) and strictly checks all field
#' types, nullability rules, enum levels, numeric bounds, string length bounds,
#' regex patterns, and key strictness without silent coercion.
#'
#' @param raw_output Character scalar JSON string (or a named R list).
#' @param schema An [extraction_schema()] object.
#'
#' @return A list with elements:
#'   - `valid`: logical scalar (`TRUE` if all checks pass)
#'   - `data`: named list of strictly typed scalar R values (when valid) or `NULL`
#'   - `errors`: character vector of specific validation diagnostic messages
#'
#' @export
#' @examples
#' sc <- extraction_schema(
#'   label = schema_field("enum", values = c("yes", "no")),
#'   score = schema_field("integer", min = 0L, max = 10L)
#' )
#' validate_extraction('{"label": "yes", "score": 7}', sc)
#' validate_extraction('{"label": "maybe", "score": 99}', sc)
validate_extraction <- function(raw_output, schema) {
  if (!inherits(schema, "airgap_schema")) {
    cli::cli_abort("{.arg schema} must be an `airgap_schema` object.", class = "airgap_validation_error")
  }

  if (is.list(raw_output) && !is.data.frame(raw_output)) {
    parsed <- raw_output
  } else {
    json_str <- extract_json_payload(raw_output)
    if (is.null(json_str)) {
      return(list(valid = FALSE, data = NULL, errors = "Model returned empty or non-character output."))
    }
    parsed <- tryCatch(
      jsonlite::fromJSON(json_str, simplifyVector = FALSE),
      error = function(e) {
        structure(list(message = conditionMessage(e)), class = "airgap_json_parse_err")
      }
    )
    if (inherits(parsed, "airgap_json_parse_err")) {
      return(list(
        valid = FALSE,
        data = NULL,
        errors = paste0("Malformed JSON: ", parsed$message)
      ))
    }
  }

  if (!is.list(parsed) || is.data.frame(parsed) || (length(parsed) > 0L && is.null(names(parsed)))) {
    return(list(valid = FALSE, data = NULL, errors = "Output must be a JSON object mapping field names to values."))
  }

  errors <- character()
  expected_keys <- names(schema$fields)
  actual_keys <- names(parsed) %||% character()

  missing_keys <- setdiff(expected_keys, actual_keys)
  if (length(missing_keys) > 0L) {
    errors <- c(errors, paste0("Missing required field(s): ", paste(missing_keys, collapse = ", "), "."))
  }

  if (isTRUE(schema$strict_keys)) {
    extra_keys <- setdiff(actual_keys, expected_keys)
    if (length(extra_keys) > 0L) {
      # Never echo untrusted raw LLM key names into error messages (zero-PII checkpoint safety)
      errors <- c(errors, paste0(
        "Unexpected extra field(s) not in schema (count: ", length(extra_keys),
        "; allowed fields: ", paste(expected_keys, collapse = ", "), ")."
      ))
    }
  }

  typed_data <- list()

  for (nm in expected_keys) {
    if (!nm %in% actual_keys) next
    f <- schema$fields[[nm]]
    val <- parsed[[nm]]

    # Nullability check
    is_null_val <- is.null(val) || (length(val) == 1L && !is.list(val) && is.na(val))
    if (is_null_val) {
      if (isTRUE(f$nullable)) {
        typed_data[[nm]] <- typed_na_for_field(f)
      } else {
        errors <- c(errors, paste0("Field '", nm, "' is null/NA but nullable = FALSE."))
      }
      next
    }

    # Scalar check (reject nested lists/arrays)
    if (is.list(val) || length(val) != 1L) {
      errors <- c(errors, paste0("Field '", nm, "' must be a scalar ", f$type, ", not an array or object."))
      next
    }

    if (identical(f$type, "character")) {
      if (!is.character(val)) {
        errors <- c(errors, paste0("Field '", nm, "' must be a character string (got ", typeof(val), ")."))
        next
      }
      nc <- nchar(val, type = "chars")
      if (!is.null(f$min_length) && nc < f$min_length) {
        errors <- c(errors, paste0("Field '", nm, "' length (", nc, ") is less than min_length (", f$min_length, ")."))
      }
      if (!is.null(f$max_length) && nc > f$max_length) {
        errors <- c(errors, paste0("Field '", nm, "' length (", nc, ") exceeds max_length (", f$max_length, ")."))
      }
      if (!is.null(f$pattern) && !grepl(f$pattern, val, perl = TRUE)) {
        errors <- c(errors, paste0("Field '", nm, "' does not match required pattern '", f$pattern, "'."))
      }
      typed_data[[nm]] <- as.character(val)
    } else if (identical(f$type, "enum")) {
      if (!is.character(val)) {
        errors <- c(errors, paste0("Field '", nm, "' must be a string enum value (got ", typeof(val), ")."))
        next
      }
      if (!val %in% f$values) {
        # Never echo untrusted raw LLM string values into error messages (zero-PII checkpoint safety)
        errors <- c(errors, paste0(
          "Field '", nm, "' value is not in allowed enum values [",
          paste(f$values, collapse = ", "), "]."
        ))
        next
      }
      typed_data[[nm]] <- as.character(val)
    } else if (identical(f$type, "integer")) {
      if (!is.numeric(val) || is.logical(val) || !is.finite(val) || val != floor(val) ||
          abs(val) > .Machine$integer.max) {
        errors <- c(errors, paste0("Field '", nm, "' must be an integer (got ", typeof(val), ")."))
        next
      }
      if (!is.null(f$min) && val < f$min) {
        errors <- c(errors, paste0("Field '", nm, "' value (", val, ") is below min (", f$min, ")."))
      }
      if (!is.null(f$max) && val > f$max) {
        errors <- c(errors, paste0("Field '", nm, "' value (", val, ") exceeds max (", f$max, ")."))
      }
      typed_data[[nm]] <- as.integer(val)
    } else if (identical(f$type, "numeric")) {
      if (!is.numeric(val) || is.logical(val) || !is.finite(val)) {
        errors <- c(errors, paste0("Field '", nm, "' must be a finite number (got ", typeof(val), ")."))
        next
      }
      if (!is.null(f$min) && val < f$min) {
        errors <- c(errors, paste0("Field '", nm, "' value (", val, ") is below min (", f$min, ")."))
      }
      if (!is.null(f$max) && val > f$max) {
        errors <- c(errors, paste0("Field '", nm, "' value (", val, ") exceeds max (", f$max, ")."))
      }
      typed_data[[nm]] <- as.numeric(val)
    } else if (identical(f$type, "logical")) {
      if (!is.logical(val) || is.na(val)) {
        errors <- c(errors, paste0("Field '", nm, "' must be a boolean true/false (got ", typeof(val), ")."))
        next
      }
      typed_data[[nm]] <- as.logical(val)
    }
  }

  if (length(errors) > 0L) {
    return(list(valid = FALSE, data = NULL, errors = errors))
  }

  list(valid = TRUE, data = typed_data, errors = character())
}

#' Build a Structured Repair Prompt for Malformed Model Outputs
#'
#' Constructs a deterministic follow-up prompt instructing the local model to
#' repair schema or JSON syntax errors reported by [validate_extraction()].
#'
#' @param original_prompt Character scalar original extraction prompt.
#' @param invalid_output Character scalar previous invalid model output.
#' @param errors Character vector of validation error messages.
#' @param schema An [extraction_schema()] object.
#'
#' @return Character scalar repair prompt string.
#'
#' @export
#' @examples
#' sc <- extraction_schema(score = schema_field("integer", min = 0L, max = 10L))
#' bad <- '{"score": 99}'
#' val <- validate_extraction(bad, sc)
#' cat(build_repair_prompt("Extract score.", bad, val$errors, sc))
build_repair_prompt <- function(original_prompt, invalid_output, errors, schema) {
  assert_scalar_string(original_prompt, "original_prompt")
  if (!inherits(schema, "airgap_schema")) {
    cli::cli_abort("{.arg schema} must be an `airgap_schema` object.", class = "airgap_validation_error")
  }
  prev <- if (is.character(invalid_output) && length(invalid_output) == 1L && !is.na(invalid_output)) {
    if (nchar(invalid_output) > 1200L) paste0(substr(invalid_output, 1L, 1200L), "...[truncated]") else invalid_output
  } else {
    "<empty>"
  }
  err_lines <- paste0("- ", errors, collapse = "\n")
  schema_json <- as.character(jsonlite::toJSON(as_json_schema(schema), auto_unbox = TRUE, pretty = TRUE))

  paste(
    original_prompt,
    "",
    "--- REPAIR INSTRUCTION ---",
    "Your previous output failed strict schema validation:",
    err_lines,
    "",
    "Previous invalid output:",
    prev,
    "",
    "Return ONLY a single valid JSON object conforming strictly to this JSON Schema (no markdown prose or extra keys):",
    schema_json,
    sep = "\n"
  )
}
