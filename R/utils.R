# Internal utilities for canonical serialization, hashing, validation, and errors

#' Format current UTC timestamp in ISO-8601 format
#' @noRd
utc_timestamp <- function(time = Sys.time()) {
  format(as.POSIXct(time, tz = "UTC"), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
}

#' Generate a compact random run identifier
#' @noRd
generate_run_id <- function(prefix = "run") {
  ts <- format(as.POSIXct(Sys.time(), tz = "UTC"), "%Y%m%dT%H%M%SZ", tz = "UTC")
  rand_hex <- paste(as.character(openssl::rand_bytes(4L)), collapse = "")
  paste0(prefix, "_", ts, "_", rand_hex)
}

#' Recursively sort named list keys for canonical deterministic JSON
#' @noRd
canonicalize_object <- function(x) {
  if (is.list(x) && !is.data.frame(x)) {
    nms <- names(x)
    if (!is.null(nms)) {
      ord <- order(nms)
      x <- x[ord]
      nms <- nms[ord]
      res <- lapply(x, canonicalize_object)
      names(res) <- nms
      return(res)
    } else {
      return(lapply(x, canonicalize_object))
    }
  }
  x
}

#' Serialize an R object into canonical deterministic JSON string
#' @noRd
canonical_json <- function(x) {
  canon <- canonicalize_object(x)
  as.character(jsonlite::toJSON(
    canon,
    auto_unbox = TRUE,
    null = "null",
    na = "null",
    digits = NA,
    POSIXt = "ISO8601",
    force = TRUE
  ))
}

#' Convert an openssl hash result cleanly to a plain scalar lowercase hex string
#' @noRd
hash_to_hex <- function(h) {
  if (is.raw(h)) {
    return(paste(as.character(unclass(h)), collapse = ""))
  }
  unname(as.character(unclass(h)))[1L]
}

#' Compute prefixed SHA-256 hex digest of a character string
#' @noRd
sha256_string <- function(x) {
  if (length(x) != 1L || is.na(x)) {
    x <- ""
  }
  paste0("sha256:", hash_to_hex(openssl::sha256(enc2utf8(as.character(x)))))
}

#' Compute prefixed SHA-256 hex digest of a canonicalized R object
#' @noRd
sha256_object <- function(x) {
  sha256_string(canonical_json(x))
}

#' Compute HMAC-SHA256 hex digest of a string using a raw or character key
#' @noRd
hmac_sha256_hex <- function(x, key) {
  key_raw <- normalize_secret_key(key)
  hash_to_hex(openssl::sha256(enc2utf8(as.character(x)), key = key_raw))
}

#' Normalize a secret key into a 32-byte raw vector
#' @noRd
normalize_secret_key <- function(key) {
  if (is.raw(key)) {
    if (length(key) < 16L) {
      cli::cli_abort(
        "Secret key raw vector must be at least 16 bytes.",
        class = "airgap_key_error"
      )
    }
    if (length(key) == 32L) {
      return(key)
    }
    return(as.raw(openssl::sha256(key)))
  }
  if (!is.character(key) || length(key) != 1L || is.na(key) || !nzchar(key)) {
    cli::cli_abort(
      "Secret key must be a non-empty scalar character string or raw vector.",
      class = "airgap_key_error"
    )
  }
  # If 64 hex characters, decode directly to 32 bytes; otherwise derive via SHA-256
  if (grepl("^[0-9a-fA-F]{64}$", key)) {
    hex_pairs <- substring(key, seq(1L, 63L, by = 2L), seq(2L, 64L, by = 2L))
    return(as.raw(strtoi(hex_pairs, base = 16L)))
  }
  as.raw(openssl::sha256(charToRaw(enc2utf8(key))))
}

#' Validate and normalize a SHA-256 digest string to lowercase "sha256:<64hex>"
#' @noRd
normalize_sha256_digest <- function(digest, allow_null = FALSE) {
  if (is.null(digest)) {
    if (allow_null) return(NULL)
    cli::cli_abort("SHA-256 digest must not be NULL.", class = "airgap_digest_error")
  }
  if (!is.character(digest) || length(digest) != 1L || is.na(digest)) {
    cli::cli_abort("SHA-256 digest must be a non-empty character scalar.", class = "airgap_digest_error")
  }
  clean <- tolower(trimws(digest))
  clean <- sub("^sha256:", "", clean)
  if (!grepl("^[0-9a-f]{64}$", clean)) {
    cli::cli_abort(
      c(
        "Invalid SHA-256 digest format.",
        "x" = "Expected 64 hexadecimal characters (optionally prefixed with 'sha256:')."
      ),
      class = "airgap_digest_error"
    )
  }
  paste0("sha256:", clean)
}

#' Check whether a value is a valid sha256 digest without throwing
#' @noRd
is_valid_sha256_digest <- function(digest) {
  if (!is.character(digest) || length(digest) != 1L || is.na(digest)) {
    return(FALSE)
  }
  clean <- sub("^sha256:", "", tolower(trimws(digest)))
  grepl("^[0-9a-f]{64}$", clean)
}

#' Shell-quote a single argument safely using POSIX single quotes
#' @noRd
sh_quote_posix <- function(x) {
  paste0("'", gsub("'", "'\"'\"'", as.character(x), fixed = TRUE), "'")
}

#' Validate non-empty character scalar
#' @noRd
assert_scalar_string <- function(x, arg = deparse(substitute(x)), allow_empty = FALSE) {
  if (!is.character(x) || length(x) != 1L || is.na(x) || (!allow_empty && !nzchar(trimws(x)))) {
    cli::cli_abort(
      "{.arg {arg}} must be a non-empty character scalar.",
      class = "airgap_validation_error"
    )
  }
  invisible(x)
}

#' Validate logical scalar
#' @noRd
assert_scalar_logical <- function(x, arg = deparse(substitute(x))) {
  if (!is.logical(x) || length(x) != 1L || is.na(x)) {
    cli::cli_abort(
      "{.arg {arg}} must be a logical scalar (`TRUE` or `FALSE`).",
      class = "airgap_validation_error"
    )
  }
  invisible(x)
}

#' Collect non-sensitive OS / R environment summary
#' @noRd
runtime_os_info <- function() {
  si <- Sys.info()
  paste(si[["sysname"]], si[["release"]], si[["machine"]])
}

#' Get package version safely during both installed and load_all execution
#' @noRd
airgapllm_version <- function() {
  tryCatch(
    as.character(utils::packageVersion("airgapllm")),
    error = function(e) "0.1.0"
  )
}
