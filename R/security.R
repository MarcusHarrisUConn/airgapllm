# Centralized Security, Cryptography, SSRF, Injection, Symlink & Unicode Guards

#' Constant-Time Byte Comparison (Eliminating Timing Side Channels)
#'
#' Compares two raw vectors or character scalars in constant time using bitwise
#' XOR accumulation without early exit. Used internally for vault HMAC-SHA256
#' authentication, SHA-256 weight digest verification, and audit chain
#' validation.
#'
#' @param a Character scalar or raw vector.
#' @param b Character scalar or raw vector.
#' @return Logical scalar `TRUE` iff `a` and `b` are byte-identical.
#' @noRd
constant_time_equal <- function(a, b) {
  if (is.character(a) && length(a) == 1L && !is.na(a)) {
    ra <- charToRaw(enc2utf8(a))
  } else if (is.raw(a)) {
    ra <- a
  } else {
    return(FALSE)
  }

  if (is.character(b) && length(b) == 1L && !is.na(b)) {
    rb <- charToRaw(enc2utf8(b))
  } else if (is.raw(b)) {
    rb <- b
  } else {
    return(FALSE)
  }

  na <- length(ra)
  nb <- length(rb)
  max_len <- max(na, nb)
  if (max_len == 0L) {
    return(na == nb)
  }

  # Fold length difference into accumulator; pad shorter vector to compare max_len bytes
  diff_acc <- bitwXor(as.integer(na), as.integer(nb))
  ia <- integer(max_len)
  ib <- integer(max_len)
  if (na > 0L) ia[seq_len(na)] <- as.integer(ra)
  if (nb > 0L) ib[seq_len(nb)] <- as.integer(rb)

  for (i in seq_len(max_len)) {
    diff_acc <- bitwOr(diff_acc, bitwXor(ia[i], ib[i]))
  }
  diff_acc == 0L
}

#' RFC 5869 HKDF-SHA256 Key Derivation (Extract + Expand)
#'
#' Derives cryptographically independent subkeys from input keying material
#' (`ikm`) with explicit `salt` and domain-separation `info`.
#'
#' @param ikm Raw vector of input keying material.
#' @param salt Raw vector or character scalar salt (defaults to 32 zero bytes).
#' @param info Character scalar or raw vector domain-separation context string.
#' @param length Positive integer output byte length (default `32L`).
#' @return Raw vector of length `length`.
#' @noRd
hkdf_sha256 <- function(ikm, salt = NULL, info = "", length = 32L) {
  if (!is.raw(ikm) || length(ikm) == 0L) {
    cli::cli_abort("HKDF input keying material must be a non-empty raw vector.", class = "airgap_key_error")
  }
  length <- as.integer(length)
  if (is.na(length) || length < 1L || length > 255L * 32L) {
    cli::cli_abort("HKDF output length must be between 1 and 8160 bytes.", class = "airgap_key_error")
  }

  if (is.null(salt) || length(salt) == 0L) {
    salt_raw <- raw(32L)
  } else if (is.raw(salt)) {
    salt_raw <- salt
  } else {
    salt_raw <- charToRaw(enc2utf8(as.character(salt)[1L]))
  }

  info_raw <- if (is.raw(info)) info else charToRaw(enc2utf8(as.character(info)[1L]))

  # HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
  prk <- as.raw(openssl::sha256(ikm, key = salt_raw))

  # HKDF-Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
  n_blocks <- as.integer(ceiling(length / 32L))
  okm <- raw(0L)
  prev <- raw(0L)
  for (i in seq_len(n_blocks)) {
    prev <- as.raw(openssl::sha256(c(prev, info_raw, as.raw(i)), key = prk))
    okm <- c(okm, prev)
  }
  okm[seq_len(length)]
}

#' Reject ASCII control characters, newlines, NUL, or non-UTF8 sequences
#' @noRd
assert_no_control_chars <- function(x, arg = deparse(substitute(x))) {
  if (!is.character(x)) return(invisible(x))
  for (s in x) {
    if (is.na(s)) next
    if (!validUTF8(s)) {
      cli::cli_abort(
        "Invalid UTF-8 byte sequence rejected in {.arg {arg}}.",
        class = "airgap_security_error"
      )
    }
    if (grepl("[\\x00-\\x1f\\x7f]", s, perl = TRUE)) {
      cli::cli_abort(
        "Control characters or newlines are prohibited in {.arg {arg}}.",
        class = "airgap_security_error"
      )
    }
  }
  invisible(x)
}

#' Strict OCI container image name validation (blocks newline/shell/YAML/Apptainer injection)
#' @noRd
assert_safe_container_image <- function(image, arg = "image") {
  assert_scalar_string(image, arg)
  assert_no_control_chars(image, arg)
  # Canonical OCI reference: [registry[:port]/]repo[/subrepo][:tag]
  pat <- "^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?$"
  if (!grepl(pat, image, perl = TRUE)) {
    cli::cli_abort(
      c(
        "Unsafe or malformed container image reference in {.arg {arg}}.",
        "x" = "Image must be a canonical lowercase OCI name (e.g., 'ollama/ollama' or 'ghcr.io/ggerganov/llama.cpp')."
      ),
      class = "airgap_security_error"
    )
  }
  invisible(image)
}

#' Protected container env var names that user env must never override
#' @noRd
protected_container_env_vars <- function() {
  c(
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "BASH_ENV", "ENV", "PROMPT_COMMAND",
    "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE",
    "DO_NOT_TRACK", "OLLAMA_NOHISTORY", "OLLAMA_HOST", "OLLAMA_MODELS"
  )
}

#' Check whether an env var name is a disallowed proxy or protected isolation override
#' @noRd
is_forbidden_container_env <- function(name) {
  up <- toupper(as.character(name)[1L])
  (up %in% protected_container_env_vars()) ||
    grepl("^(HTTP|HTTPS|ALL|FTP|SOCKS|SOCKS4|SOCKS5|NO)_PROXY$", up, perl = TRUE)
}

#' Validate POSIX environment variable name and value
#' @noRd
assert_safe_env_entry <- function(name, value) {
  assert_no_control_chars(name, "env name")
  if (!grepl("^[A-Za-z_][A-Za-z0-9_]{0,127}$", name, perl = TRUE)) {
    cli::cli_abort(
      "Unsafe environment variable name {.val {name}}: must match `^[A-Za-z_][A-Za-z0-9_]*$`.",
      class = "airgap_security_error"
    )
  }
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    cli::cli_abort("Environment variable {.val {name}} must have a scalar string value.", class = "airgap_validation_error")
  }
  assert_no_control_chars(value, paste0("env[['", name, "']]"))
  # Block dangerous dynamic-linker, shell-injection, proxy, and offline-isolation overrides
  if (is_forbidden_container_env(name)) {
    cli::cli_abort(
      "Protected or dangerous environment variable {.val {name}} cannot be overridden in hardened air-gapped containers.",
      class = "airgap_security_error"
    )
  }
  invisible(TRUE)
}

#' Validate a local host filesystem path for safe container bind mounting or local output
#' @noRd
assert_safe_host_path <- function(
  path,
  arg = "path",
  forbid_colon = TRUE,
  allow_windows_path = identical(.Platform$OS.type, "windows")
) {
  assert_scalar_string(path, arg)
  assert_no_control_chars(path, arg)

  # Reject leading-dash paths (CLI option injection defense)
  if (startsWith(trimws(path), "-")) {
    cli::cli_abort(
      "Leading-dash path rejected in {.arg {arg}} to prevent CLI flag injection.",
      class = "airgap_security_error"
    )
  }

  # Reject shell metacharacters (and backslashes unless valid Windows filesystem path)
  bad_pat <- if (isTRUE(allow_windows_path)) "[`$|;&<>]" else "[\\\\`$|;&<>]"
  if (grepl(bad_pat, path, perl = TRUE)) {
    cli::cli_abort(
      "Unsafe shell metacharacter or backslash rejected in {.arg {arg}}.",
      class = "airgap_security_error"
    )
  }

  # Reject bind-mount option injection (':'), permitting only a Windows drive prefix (e.g. C:\ or C:/)
  colon_check_str <- if (isTRUE(allow_windows_path) && grepl("^[A-Za-z]:[/\\\\]", path, perl = TRUE)) {
    substr(path, 3L, nchar(path))
  } else {
    path
  }
  if (isTRUE(forbid_colon) && grepl(":", colon_check_str, fixed = TRUE)) {
    cli::cli_abort(
      "Colon (':') is prohibited in {.arg {arg}} to prevent Docker/Apptainer bind-mount option injection.",
      class = "airgap_security_error"
    )
  }

  # Reject path traversal segments ("..") across both POSIX and Windows separators
  norm_seps <- if (isTRUE(allow_windows_path)) gsub("\\\\", "/", path) else path
  segs <- strsplit(norm_seps, "/", fixed = TRUE)[[1L]]
  if (any(segs == "..")) {
    cli::cli_abort(
      "Path traversal ('..') is prohibited in {.arg {arg}}.",
      class = "airgap_security_error"
    )
  }
  invisible(path)
}

#' Validate a relative model filename inside model_dir (blocks traversal & injection)
#' @noRd
assert_safe_model_file <- function(model_file, arg = "model_file") {
  assert_scalar_string(model_file, arg)
  assert_no_control_chars(model_file, arg)
  if (startsWith(model_file, "/") || startsWith(model_file, "~")) {
    cli::cli_abort(
      "{.arg {arg}} must be a relative filename inside `model_dir`, not an absolute path.",
      class = "airgap_security_error"
    )
  }
  if (grepl("[\\\\`$|;&<>:]", model_file, perl = TRUE)) {
    cli::cli_abort(
      "Unsafe characters rejected in {.arg {arg}}.",
      class = "airgap_security_error"
    )
  }
  segs <- strsplit(model_file, "/", fixed = TRUE)[[1L]]
  if (any(segs == ".." | segs == "." | !nzchar(segs))) {
    cli::cli_abort(
      "Path traversal or empty path segments are prohibited in {.arg {arg}}.",
      class = "airgap_security_error"
    )
  }
  if (!grepl("^[A-Za-z0-9._/-]+$", model_file, perl = TRUE)) {
    cli::cli_abort(
      "{.arg {arg}} contains disallowed characters (allowed: letters, digits, '.', '_', '-', '/').",
      class = "airgap_security_error"
    )
  }
  invisible(model_file)
}

#' Validate structured container tokens (names, limits, GPU selectors, caps, network mode)
#' @noRd
assert_safe_token <- function(x, arg, pattern, description) {
  assert_scalar_string(x, arg)
  assert_no_control_chars(x, arg)
  if (!grepl(pattern, x, perl = TRUE)) {
    cli::cli_abort(
      "Unsafe or invalid {.arg {arg}}: expected {description}.",
      class = "airgap_security_error"
    )
  }
  invisible(x)
}

#' Validate backend extra_args against shell injection and container security overrides
#' @noRd
assert_safe_extra_args <- function(extra_args) {
  if (length(extra_args) == 0L) return(invisible(extra_args))
  if (!is.character(extra_args) || any(is.na(extra_args))) {
    cli::cli_abort("{.arg extra_args} must be a character vector with no NA values.", class = "airgap_validation_error")
  }
  assert_no_control_chars(extra_args, "extra_args")

  forbidden_flags <- c(
    "--privileged", "--cap-add", "--network", "--net", "--pid", "--ipc",
    "--uts", "--userns", "--volume", "-v", "--mount", "--security-opt",
    "--device", "--publish", "-p", "--add-host",
    "--trust-remote-code", "--download-dir"
  )

  for (i in seq_along(extra_args)) {
    a <- extra_args[i]
    if (grepl("[`$|;&<>\\\\]", a, perl = TRUE) || grepl("\\$\\(", a, perl = TRUE)) {
      cli::cli_abort(
        "Shell metacharacters are prohibited in {.arg extra_args}.",
        class = "airgap_security_error"
      )
    }
    flag_key <- tolower(sub("=.*$", "", a))
    if (flag_key %in% forbidden_flags) {
      cli::cli_abort(
        "Security-override flag {.val {flag_key}} is prohibited in {.arg extra_args}.",
        class = "airgap_security_error"
      )
    }
    # Block non-loopback --host overrides inside backend args
    if (identical(flag_key, "--host")) {
      host_val <- if (grepl("=", a, fixed = TRUE)) {
        sub("^[^=]+=", "", a)
      } else if (i < length(extra_args)) {
        extra_args[i + 1L]
      } else {
        ""
      }
      if (!tolower(host_val) %in% c("127.0.0.1", "localhost", "::1")) {
        cli::cli_abort(
          "Non-loopback `--host` override ({.val {host_val}}) is prohibited in {.arg extra_args}.",
          class = "airgap_security_error"
        )
      }
    }
  }
  invisible(extra_args)
}

#' Strip trailing path separators while preserving POSIX "/" and Windows drive roots ("C:/")
#' @noRd
strip_trailing_sep <- function(path) {
  if (identical(path, "/") || grepl("^[A-Za-z]:[/\\\\]?$", path, perl = TRUE)) {
    return(path)
  }
  sub("[/\\\\]+$", "", path, perl = TRUE)
}

#' Canonicalize a path for cross-platform equality/prefix comparisons
#' Expands Windows 8.3 short paths (e.g. RUNNER~1) via deepest existing ancestor and
#' uses case-insensitive forward-slash form on Windows.
#' @noRd
canonical_compare_path <- function(path) {
  p <- strip_trailing_sep(path)
  if (file.exists(p) || dir.exists(p)) {
    canon <- strip_trailing_sep(normalizePath(p, winslash = "/", mustWork = TRUE))
    return(if (identical(.Platform$OS.type, "windows")) tolower(canon) else canon)
  }
  tail_parts <- character()
  cur <- p
  for (step in seq_len(64L)) {
    parent <- dirname(cur)
    if (identical(parent, cur)) break
    tail_parts <- c(basename(cur), tail_parts)
    cur <- strip_trailing_sep(parent)
    if (file.exists(cur) || dir.exists(cur)) {
      base_canon <- strip_trailing_sep(normalizePath(cur, winslash = "/", mustWork = TRUE))
      joined <- if (length(tail_parts) > 0L) paste(c(base_canon, tail_parts), collapse = "/") else base_canon
      return(if (identical(.Platform$OS.type, "windows")) tolower(joined) else joined)
    }
  }
  canon <- strip_trailing_sep(normalizePath(p, winslash = "/", mustWork = FALSE))
  if (identical(.Platform$OS.type, "windows")) tolower(canon) else canon
}

#' Check whether a path is a symbolic link
#' @noRd
is_symlink_path <- function(path) {
  rl <- suppressWarnings(Sys.readlink(path))
  !is.na(rl) && nzchar(rl)
}

#' Check whether a path is a canonical macOS root OS symlink alias (/var, /tmp, /etc)
#' @noRd
is_macos_os_root_alias <- function(path) {
  identical(Sys.info()[["sysname"]], "Darwin") &&
    sub("/+$", "", path) %in% c("/var", "/tmp", "/etc")
}

#' Verify that a write destination and its ancestor chain contain no symbolic links or escapes
#' @noRd
assert_safe_write_target <- function(path, root_dir = NULL, arg = "path") {
  assert_scalar_string(path, arg)
  assert_no_control_chars(path, arg)

  segs <- strsplit(gsub("\\\\", "/", path), "/", fixed = TRUE)[[1L]]
  if (any(segs == "..")) {
    cli::cli_abort(
      "Path traversal ('..') is prohibited in {.arg {arg}}: {.path {path}}.",
      class = "airgap_security_error"
    )
  }

  # Strip trailing slashes before symlink check (trailing slash dereferences dir symlinks on POSIX)
  clean_path <- strip_trailing_sep(path)
  if (is_symlink_path(clean_path)) {
    cli::cli_abort(
      "Refusing to write through symbolic link in {.arg {arg}}: {.path {clean_path}}.",
      class = "airgap_security_error"
    )
  }

  cmp_root <- if (!is.null(root_dir)) canonical_compare_path(root_dir) else NULL

  # Walk existing ancestor components to reject symlinked parent directories
  cur <- clean_path
  for (step in seq_len(64L)) {
    parent <- dirname(cur)
    if (identical(parent, cur)) break
    parent_clean <- strip_trailing_sep(parent)
    if (is_symlink_path(parent_clean) && !is_macos_os_root_alias(parent_clean)) {
      cli::cli_abort(
        "Refusing to write through symlinked parent directory in {.arg {arg}}: {.path {parent_clean}}.",
        class = "airgap_security_error"
      )
    }
    if (!is.null(cmp_root) && identical(canonical_compare_path(parent_clean), cmp_root)) {
      break
    }
    cur <- parent_clean
  }

  if (!is.null(root_dir)) {
    canon_root <- canonical_compare_path(root_dir)
    parent_dir <- dirname(clean_path)
    if (dir.exists(parent_dir)) {
      canon_parent <- canonical_compare_path(parent_dir)
      root_prefix <- if (endsWith(canon_root, "/")) canon_root else paste0(canon_root, "/")
      if (!identical(canon_parent, canon_root) && !startsWith(canon_parent, root_prefix)) {
        cli::cli_abort(
          "Write target escapes allowed root directory in {.arg {arg}}.",
          class = "airgap_security_error"
        )
      }
    }
  }
  invisible(TRUE)
}

#' Verify that target_path does not escape root_dir via symlinks or traversal
#' @noRd
assert_path_confined <- function(target_path, root_dir = NULL, allow_symlinks = FALSE) {
  assert_scalar_string(target_path, "path")
  assert_no_control_chars(target_path, "path")

  segs <- strsplit(gsub("\\\\", "/", target_path), "/", fixed = TRUE)[[1L]]
  if (any(segs == "..")) {
    cli::cli_abort(
      "Path traversal ('..') is prohibited in {.path {target_path}}.",
      class = "airgap_security_error"
    )
  }

  clean_target <- strip_trailing_sep(target_path)
  if (!isTRUE(allow_symlinks) && is_symlink_path(clean_target)) {
    cli::cli_abort(
      "Symbolic link rejected under air-gap model integrity policy: {.path {clean_target}}.",
      class = "airgap_security_error"
    )
  }

  if (!is.null(root_dir)) {
    canon_root <- canonical_compare_path(root_dir)
    canon_target <- canonical_compare_path(target_path)
    root_prefix <- if (endsWith(canon_root, "/")) canon_root else paste0(canon_root, "/")
    if (!identical(canon_target, canon_root) && !startsWith(canon_target, root_prefix)) {
      cli::cli_abort(
        c(
          "Symlink or path escape detected outside model root directory.",
          "x" = "Target resolved to: {.path {canon_target}}",
          "x" = "Allowed root:       {.path {canon_root}}"
        ),
        class = "airgap_security_error"
      )
    }

    # Walk relative segments from target_path up to root_dir to catch intermediate symlinked directories
    if (!isTRUE(allow_symlinks)) {
      cur <- clean_target
      for (step in seq_len(64L)) {
        if (is_symlink_path(cur)) {
          cli::cli_abort(
            "Symbolic link component rejected inside model directory: {.path {cur}}.",
            class = "airgap_security_error"
          )
        }
        if (identical(canonical_compare_path(cur), canon_root)) {
          break
        }
        parent <- dirname(cur)
        if (identical(parent, cur)) {
          break
        }
        cur <- strip_trailing_sep(parent)
      }
    }
  } else if (!isTRUE(allow_symlinks)) {
    # Even without root_dir, walk ancestor path components to reject symlinked parent directories
    cur <- clean_target
    for (step in seq_len(64L)) {
      parent <- dirname(cur)
      if (identical(parent, cur)) break
      parent_clean <- strip_trailing_sep(parent)
      if (is_symlink_path(parent_clean) && !is_macos_os_root_alias(parent_clean)) {
        cli::cli_abort(
          "Symbolic link parent directory rejected under air-gap model integrity policy: {.path {parent_clean}}.",
          class = "airgap_security_error"
        )
      }
      cur <- parent_clean
    }
  }
  invisible(TRUE)
}

#' Detect Active Outbound Proxy Environment Variables (Case-Insensitive)
#'
#' Audits all active process environment variables for proxy settings and
#' checks whether `NO_PROXY` explicitly covers loopback hosts (`127.0.0.1`,
#' `localhost`, and `::1` when targeting IPv6 loopback) as exact tokens.
#'
#' @noRd
detect_outbound_proxies <- function(endpoint_host = NULL) {
  all_env <- Sys.getenv()
  nms <- names(all_env)
  vals <- unname(as.character(all_env))

  is_proxy_var <- grepl("^(http|https|all|ftp|socks|socks4|socks5)_proxy$", nms, ignore.case = TRUE)
  active_idx <- which(is_proxy_var & nzchar(trimws(vals)))
  active_vars <- nms[active_idx]

  no_proxy_idx <- which(tolower(nms) == "no_proxy" & nzchar(trimws(vals)))
  no_proxy_tokens <- character()
  if (length(no_proxy_idx) > 0L) {
    raw_toks <- unlist(strsplit(paste(vals[no_proxy_idx], collapse = ","), ",", fixed = TRUE), use.names = FALSE)
    no_proxy_tokens <- tolower(trimws(raw_toks))
    no_proxy_tokens <- no_proxy_tokens[nzchar(no_proxy_tokens)]
  }

  has_ipv4_bypass <- ("127.0.0.1" %in% no_proxy_tokens) && ("localhost" %in% no_proxy_tokens)
  has_ipv6_bypass <- any(no_proxy_tokens %in% c("::1", "[::1]"))
  needs_ipv6 <- is.character(endpoint_host) && length(endpoint_host) == 1L && identical(tolower(endpoint_host), "::1")
  has_local_bypass <- if (needs_ipv6) (has_ipv4_bypass && has_ipv6_bypass) else has_ipv4_bypass

  list(
    active_vars = sort(unique(active_vars)),
    has_local_bypass = has_local_bypass,
    has_ipv6_bypass = has_ipv6_bypass,
    needs_ipv6 = needs_ipv6
  )
}

#' Strictly Parse and Classify an Endpoint URL Against SSRF / Parser Bypasses
#'
#' Enforces canonical local-only endpoints (`127.0.0.1`, `localhost`, `[::1]`,
#' `unix:///...`, or `mock://offline`). Explicitly blocks:
#' - control chars, CRLF, leading/trailing whitespace, non-ASCII / homoglyphs
#' - backslash confusion (`http://127.0.0.1\@evil.com`)
#' - userinfo (`@`), URL fragments (`#`), percent-encoding (`%`) in authority
#' - IPv6-mapped IPv4 (`[::ffff:169.254.169.254]`, `[::ffff:7f00:1]`)
#' - octal/hex/decimal/shorthand IP notations (`0177.0.0.1`, `2130706433`, `0x7f000001`, `127.1`)
#' - DNS-rebinding & trailing-dot tricks (`localhost.evil.com`, `127.0.0.1.nip.io`, `localhost.`)
#' - wildcard bind (`0.0.0.0`, `[::]`) and private LAN/cloud metadata IPs (`169.254.169.254`, `10.x`, etc.)
#'
#' @noRd
classify_endpoint_strict <- function(endpoint) {
  if (inherits(endpoint, "airgap_runtime")) {
    endpoint <- endpoint$endpoint
  }
  if (!is.character(endpoint) || length(endpoint) != 1L || is.na(endpoint) || !nzchar(endpoint)) {
    return(list(allowed = FALSE, endpoint_class = "invalid", host = NA_character_, reason = "Endpoint is empty or non-character."))
  }

  # Reject invalid UTF-8, non-ASCII characters, control characters (including CR/LF/TAB/NUL), or ANY whitespace
  if (!validUTF8(endpoint)) {
    return(list(allowed = FALSE, endpoint_class = "invalid", host = NA_character_, reason = "Endpoint contains invalid UTF-8 bytes."))
  }
  ep_bytes <- charToRaw(endpoint)
  if (length(ep_bytes) == 0L || any(ep_bytes < as.raw(0x21) | ep_bytes > as.raw(0x7e))) {
    return(list(allowed = FALSE, endpoint_class = "invalid", host = NA_character_, reason = "Endpoint contains whitespace, control characters (CR/LF), or non-ASCII characters."))
  }
  if (grepl("\\\\", endpoint, perl = TRUE)) {
    return(list(allowed = FALSE, endpoint_class = "remote_rejected", host = NA_character_, reason = "Backslash ('\\') is prohibited in endpoints (URL parser confusion defense)."))
  }
  if (grepl("#", endpoint, fixed = TRUE)) {
    return(list(allowed = FALSE, endpoint_class = "remote_rejected", host = NA_character_, reason = "URL fragment ('#') is prohibited in local runtime endpoints."))
  }

  # Exact offline mock endpoint
  if (identical(tolower(endpoint), "mock://offline")) {
    return(list(allowed = TRUE, endpoint_class = "offline_mock", host = "offline", reason = "Built-in offline mock runtime."))
  }

  # Strict Unix domain socket endpoint
  if (grepl("^unix:///", endpoint, ignore.case = TRUE)) {
    sock_path <- sub("^unix://", "", endpoint, ignore.case = TRUE)
    segs <- strsplit(sock_path, "/", fixed = TRUE)[[1L]]
    if (any(segs == "..") || grepl("[@%?;|&$`<>\\\\]", sock_path, perl = TRUE)) {
      return(list(allowed = FALSE, endpoint_class = "invalid", host = NA_character_, reason = "Unix socket path contains traversal ('..') or disallowed shell/URL characters."))
    }
    return(list(allowed = TRUE, endpoint_class = "unix_socket", host = "unix", reason = "Local Unix domain socket."))
  }

  # Only canonical http:// or https:// permitted for TCP loopback
  if (!grepl("^https?://", endpoint, ignore.case = TRUE)) {
    return(list(allowed = FALSE, endpoint_class = "disallowed_scheme", host = NA_character_, reason = "Only http://, https://, unix:///, or mock://offline endpoints are permitted."))
  }

  rest <- sub("^https?://", "", endpoint, ignore.case = TRUE)
  authority <- sub("[/?].*$", "", rest)
  path_query <- if (nchar(rest) > nchar(authority)) substr(rest, nchar(authority) + 1L, nchar(rest)) else ""

  if (!nzchar(authority)) {
    return(list(allowed = FALSE, endpoint_class = "invalid", host = NA_character_, reason = "Missing authority/host component."))
  }

  # Reject userinfo (@) and percent-encoding (%) inside authority completely
  if (grepl("@", authority, fixed = TRUE)) {
    return(list(allowed = FALSE, endpoint_class = "remote_rejected", host = authority, reason = "Userinfo ('@') is prohibited in local air-gapped endpoints."))
  }
  if (grepl("%", authority, fixed = TRUE)) {
    return(list(allowed = FALSE, endpoint_class = "remote_rejected", host = authority, reason = "Percent-encoding ('%') is prohibited in endpoint authority."))
  }

  # Reject path traversal in URL path
  if (nzchar(path_query)) {
    path_only <- sub("\\?.*$", "", path_query)
    if (any(strsplit(path_only, "/", fixed = TRUE)[[1L]] == "..")) {
      return(list(allowed = FALSE, endpoint_class = "invalid", host = NA_character_, reason = "Path traversal ('..') is prohibited in endpoint URL path."))
    }
  }

  # Parse strictly canonical IPv6 bracketed host or ASCII host[:port]
  if (startsWith(authority, "[")) {
    m <- regexec("^\\[([^\\]]+)\\](?::([1-9][0-9]{0,4}))?$", authority, perl = TRUE)
    parts <- regmatches(authority, m)[[1L]]
    if (length(parts) == 0L) {
      return(list(allowed = FALSE, endpoint_class = "invalid", host = authority, reason = "Malformed IPv6 authority or non-canonical port."))
    }
    host <- tolower(parts[2L])
    port_str <- if (length(parts) >= 3L) parts[3L] else ""
    # Strictly allow ONLY canonical "::1" (rejects ::ffff:127.0.0.1, ::ffff:169.254.169.254, 0:0:0:0:0:0:0:1, ::, etc.)
    if (!identical(host, "::1")) {
      return(list(
        allowed = FALSE,
        endpoint_class = "remote_rejected",
        host = host,
        reason = paste0("Non-canonical or non-loopback IPv6 host rejected: '[", host, "]'.")
      ))
    }
  } else {
    if (grepl(":", authority, fixed = TRUE)) {
      m <- regexec("^([^:]+):([1-9][0-9]{0,4})$", authority, perl = TRUE)
      parts <- regmatches(authority, m)[[1L]]
      if (length(parts) == 0L) {
        return(list(allowed = FALSE, endpoint_class = "invalid", host = authority, reason = "Malformed host:port authority (or leading-zero port)."))
      }
      host <- tolower(parts[2L])
      port_str <- parts[3L]
    } else {
      host <- tolower(authority)
      port_str <- ""
    }
    # Strictly allow ONLY exact canonical "127.0.0.1" or "localhost"
    if (!host %in% c("127.0.0.1", "localhost")) {
      return(list(
        allowed = FALSE,
        endpoint_class = "remote_rejected",
        host = host,
        reason = paste0("Non-canonical or non-loopback host rejected under air-gap policy: '", host, "'.")
      ))
    }
  }

  if (nzchar(port_str)) {
    p <- suppressWarnings(as.integer(port_str))
    if (is.na(p) || p < 1L || p > 65535L) {
      return(list(allowed = FALSE, endpoint_class = "invalid", host = host, reason = "Port number out of valid 1..65535 range."))
    }
  }

  list(
    allowed = TRUE,
    endpoint_class = "loopback",
    host = host,
    reason = paste0("Verified canonical loopback host (", host, ").")
  )
}

#' HIPAA Safe Harbor Restricted 3-Digit US ZIP Prefixes (45 CFR 164.514(b)(2))
#'
#' Returns the 17 three-digit US ZIP code prefixes whose population is 20,000
#' or fewer under HHS HIPAA Safe Harbor guidance and therefore must be
#' redacted/zeroed (`000`) even when generalizing geographic data.
#'
#' @return Character vector of 17 three-digit ZIP prefixes.
#' @export
#' @examples
#' hipaa_restricted_zip3()
hipaa_restricted_zip3 <- function() {
  c(
    "036", "059", "063", "102", "203", "556", "692", "790", "821",
    "823", "830", "831", "878", "879", "884", "890", "893"
  )
}

#' Valid 2-letter US state and territory postal codes for ZIP context matching
#' @noRd
us_state_codes <- function() {
  c(
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA",
    "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY",
    "NC", "ND", "OH", "OK", "OR", "PA", "PR", "RI", "SC", "SD", "TN",
    "TX", "UT", "VT", "VA", "VI", "WA", "WV", "WI", "WY"
  )
}

#' Index-Preserving Unicode Homoglyph and Zero-Width Canonicalizer for PII Detection
#'
#' Normalizes adversarial Unicode obfuscators (zero-width joiners/spaces, soft
#' hyphens, Unicode dashes, NBSP, fullwidth ASCII, Cyrillic/Greek confusable
#' homoglyphs) into a canonical detection string while maintaining an exact
#' integer map (`orig_idx`) back to character offsets in the original text.
#'
#' @param text Scalar character string.
#' @return List with `canonical` (string), `orig_idx` (integer vector mapping
#'   each canonical char position to its 1-based char offset in `text`), and
#'   `had_obfuscation` (logical).
#' @noRd
canonicalize_pii_text <- function(text) {
  if (is.na(text) || !nzchar(text)) {
    return(list(canonical = text, orig_idx = integer(), orig_end_idx = integer(), had_obfuscation = FALSE))
  }

  cp <- utf8ToInt(enc2utf8(text))
  n <- length(cp)

  # Fast path for pure printable ASCII (zero allocation overhead on normal text)
  if (all(cp >= 9L & cp <= 126L)) {
    idx <- seq_len(n)
    return(list(canonical = text, orig_idx = idx, orig_end_idx = idx, had_obfuscation = FALSE))
  }

  # Unicode combining diacritical marks & variation selectors (stripped from matching view;
  # trailing combining marks stay attached to their base char via orig_end_idx)
  is_combining <- (cp >= 0x0300L & cp <= 0x036FL) |
    (cp >= 0x1AB0L & cp <= 0x1AFFL) |
    (cp >= 0x1DC0L & cp <= 0x1DFFL) |
    (cp >= 0x20D0L & cp <= 0x20FFL) |
    (cp >= 0xFE00L & cp <= 0xFE0FL) |
    (cp >= 0xFE20L & cp <= 0xFE2FL)

  # Zero-width / invisible obfuscators stripped from canonical matching view
  # U+00AD soft hyphen, U+034F combining grapheme joiner (also in combining), U+180E,
  # U+200B..U+200F, U+202A..U+202E bidi overrides, U+2060..U+2064, U+FEFF BOM/ZWNBSP
  is_invisible <- is_combining |
    (cp == 0x00ADL) | (cp == 0x180EL) |
    (cp >= 0x200BL & cp <= 0x200FL) |
    (cp >= 0x202AL & cp <= 0x202EL) |
    (cp >= 0x2060L & cp <= 0x2064L) |
    (cp == 0xFEFFL)

  out_cp <- cp
  had_obf <- any(is_invisible)

  # Unicode whitespace -> ASCII space (0x20)
  is_usp <- (cp == 0x00A0L) | (cp >= 0x2000L & cp <= 0x200AL) |
    (cp == 0x202FL) | (cp == 0x205FL) | (cp == 0x3000L)
  if (any(is_usp)) {
    out_cp[is_usp] <- 0x20L
    had_obf <- TRUE
  }

  # Unicode hyphens / dashes / minus -> ASCII hyphen-minus '-' (0x2D)
  is_udash <- (cp >= 0x2010L & cp <= 0x2015L) | (cp == 0x2212L) |
    (cp == 0xFE58L) | (cp == 0xFE63L) | (cp == 0xFF0DL)
  if (any(is_udash)) {
    out_cp[is_udash] <- 0x2DL
    had_obf <- TRUE
  }

  # Fullwidth ASCII (U+FF01..U+FF5E -> 0x21..0x7E)
  is_fw <- (cp >= 0xFF01L & cp <= 0xFF5EL)
  if (any(is_fw)) {
    out_cp[is_fw] <- cp[is_fw] - 0xFEE0L
    had_obf <- TRUE
  }

  # Common Cyrillic & Greek confusable homoglyphs -> Latin ASCII
  homoglyph_from <- c(
    # Cyrillic lowercase
    0x0430L, 0x0435L, 0x043EL, 0x0440L, 0x0441L, 0x0443L, 0x0445L, 0x0456L, 0x0458L, 0x0455L,
    # Cyrillic uppercase
    0x0410L, 0x0412L, 0x0415L, 0x041AL, 0x041CL, 0x041DL, 0x041EL, 0x0420L, 0x0421L, 0x0422L, 0x0425L, 0x0406L, 0x0408L, 0x0405L,
    # Greek lowercase
    0x03B1L, 0x03B5L, 0x03BFL, 0x03C1L, 0x03C5L, 0x03C7L,
    # Greek uppercase
    0x0391L, 0x0392L, 0x0395L, 0x0396L, 0x0397L, 0x0399L, 0x039AL, 0x039CL, 0x039DL, 0x039FL, 0x03A1L, 0x03A4L, 0x03A7L,
    # Curly apostrophe / quotes -> ASCII apostrophe
    0x2018L, 0x2019L
  )
  homoglyph_to <- utf8ToInt("aeopcyxijsABEKMHOPCTXIJSaeopuxABEZHIKMNOPTX''")

  m_idx <- match(out_cp, homoglyph_from)
  hit <- !is.na(m_idx)
  if (any(hit)) {
    out_cp[hit] <- homoglyph_to[m_idx[hit]]
    had_obf <- TRUE
  }

  # Latin-1 Supplement & Latin Extended-A accented letters -> ASCII base letters
  # (enables accurate detection of accented names like "Dr. José García", "Élodie Müller")
  latin_from <- c(
    # Uppercase Latin-1: À Á Â Ã Ä Å Ç È É Ê Ë Ì Í Î Ï Ñ Ò Ó Ô Õ Ö Ø Ù Ú Û Ü Ý
    0x00C0L, 0x00C1L, 0x00C2L, 0x00C3L, 0x00C4L, 0x00C5L, 0x00C7L,
    0x00C8L, 0x00C9L, 0x00CAL, 0x00CBL, 0x00CCL, 0x00CDL, 0x00CEL, 0x00CFL,
    0x00D1L, 0x00D2L, 0x00D3L, 0x00D4L, 0x00D5L, 0x00D6L, 0x00D8L,
    0x00D9L, 0x00DAL, 0x00DBL, 0x00DCL, 0x00DDL,
    # Lowercase Latin-1: à á â ã ä å ç è é ê ë ì í î ï ñ ò ó ô õ ö ø ù ú û ü ý ÿ
    0x00E0L, 0x00E1L, 0x00E2L, 0x00E3L, 0x00E4L, 0x00E5L, 0x00E7L,
    0x00E8L, 0x00E9L, 0x00EAL, 0x00EBL, 0x00ECL, 0x00EDL, 0x00EEL, 0x00EFL,
    0x00F1L, 0x00F2L, 0x00F3L, 0x00F4L, 0x00F5L, 0x00F6L, 0x00F8L,
    0x00F9L, 0x00FAL, 0x00FBL, 0x00FCL, 0x00FDL, 0x00FFL,
    # Common Latin Extended-A: Ć ć Č č Ď ď Ę ę Ě ě Ğ ğ Ł ł Ń ń Ň ň Ő ő Ř ř Ś ś Ş ş Š š Ť ť Ů ů Ű ű Ź ź Ż ż Ž ž
    0x0106L, 0x0107L, 0x010CL, 0x010DL, 0x010EL, 0x010FL,
    0x0118L, 0x0119L, 0x011AL, 0x011BL, 0x011EL, 0x011FL,
    0x0141L, 0x0142L, 0x0143L, 0x0144L, 0x0147L, 0x0148L,
    0x0150L, 0x0151L, 0x0158L, 0x0159L, 0x015AL, 0x015BL,
    0x015EL, 0x015FL, 0x0160L, 0x0161L, 0x0164L, 0x0165L,
    0x016EL, 0x016FL, 0x0170L, 0x0171L, 0x0179L, 0x017AL,
    0x017BL, 0x017CL, 0x017DL, 0x017EL
  )
  latin_to <- utf8ToInt(paste0(
    "AAAAAACEEEEIIIINOOOOOOUUUUY",
    "aaaaaaceeeeiiiinoooooouuuuyy",
    "CcCcDdEeEeGgLlNnNnOoRrSsSsSsTtUuUuZzZzZz"
  ))

  l_idx <- match(out_cp, latin_from)
  l_hit <- !is.na(l_idx)
  if (any(l_hit)) {
    out_cp[l_hit] <- latin_to[l_idx[l_hit]]
  }

  keep <- !is_invisible
  orig_idx <- which(keep)
  orig_end_idx <- orig_idx
  if (length(orig_idx) > 0L && any(is_combining)) {
    for (k in seq_along(orig_idx)) {
      en <- orig_idx[k]
      while (en < n && is_combining[en + 1L]) {
        en <- en + 1L
      }
      orig_end_idx[k] <- en
    }
  }

  list(
    canonical = intToUtf8(out_cp[keep]),
    orig_idx = orig_idx,
    orig_end_idx = orig_end_idx,
    had_obfuscation = had_obf
  )
}

#' Safely read raw byte lines from a JSONL file, validating UTF-8 and detecting NUL bytes
#' @noRd
read_jsonl_raw_lines <- function(path) {
  sz <- file.info(path)$size
  if (is.na(sz) || sz == 0) {
    return(list())
  }
  con <- file(path, open = "rb")
  on.exit(try(close(con), silent = TRUE), add = TRUE)
  raw_bytes <- readBin(con, what = "raw", n = sz)
  if (length(raw_bytes) == 0L) return(list())

  nl_pos <- which(raw_bytes == as.raw(0x0a))
  starts <- c(1L, nl_pos + 1L)
  ends <- c(nl_pos - 1L, length(raw_bytes))

  out <- list()
  for (i in seq_along(starts)) {
    st <- starts[i]
    en <- ends[i]
    if (st > length(raw_bytes)) break
    if (en < st) next
    chunk <- raw_bytes[st:en]
    # Strip trailing CR (0x0d)
    if (length(chunk) > 0L && chunk[length(chunk)] == as.raw(0x0d)) {
      chunk <- chunk[-length(chunk)]
    }
    if (length(chunk) == 0L) next
    has_nul <- any(chunk == as.raw(0x00))
    if (has_nul) {
      out[[length(out) + 1L]] <- list(text = NA_character_, valid_utf8 = FALSE, has_nul = TRUE)
      next
    }
    txt <- rawToChar(chunk)
    Encoding(txt) <- "UTF-8"
    ok_utf8 <- isTRUE(validUTF8(txt))
    # Skip whitespace-only valid lines
    if (ok_utf8 && !nzchar(trimws(txt))) next
    out[[length(out) + 1L]] <- list(text = if (ok_utf8) txt else NA_character_, valid_utf8 = ok_utf8, has_nul = FALSE)
  }
  out
}
