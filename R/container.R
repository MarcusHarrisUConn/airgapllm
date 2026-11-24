# Pillar 1: Air-Gapped Container Lifecycle Manager

#' Default container image and port for a supported local LLM backend
#' @noRd
backend_defaults <- function(backend) {
  switch(
    backend,
    "ollama" = list(
      image = "ollama/ollama",
      port = 11434L,
      container_model_dir = "/models"
    ),
    "llama.cpp" = list(
      image = "ghcr.io/ggerganov/llama.cpp",
      port = 8080L,
      container_model_dir = "/models"
    ),
    "vllm" = list(
      image = "vllm/vllm-openai",
      port = 8000L,
      container_model_dir = "/models"
    )
  )
}

#' Define a Hardened Air-Gapped Local LLM Container Specification
#'
#' Creates a validated, digest-pinned container specification for running local
#' open-weights LLM inference backends (`"ollama"`, `"llama.cpp"`, or `"vllm"`)
#' under strict network isolation (`--network none`), a read-only root
#' filesystem, dropped Linux capabilities, and read-only local model mounts.
#'
#' @param backend Character scalar selecting the local inference runtime:
#'   `"ollama"`, `"llama.cpp"`, or `"vllm"`.
#' @param image Character scalar container image name (without tag or digest, or
#'   with `@sha256:...` embedded). Defaults to the standard upstream image for
#'   `backend`.
#' @param image_digest Character scalar pinned SHA-256 image digest
#'   (`"sha256:<64 hex chars>"`), or `NULL` if embedded in `image` or deferred
#'   for inspection by [preflight_isolation_check()].
#' @param model_dir Character scalar local host directory containing model
#'   weights, mounted read-only at `/models` inside the container.
#' @param model_file Optional character scalar filename (relative to
#'   `model_dir`) or full path to the GGUF/safetensors model weights.
#' @param model_digest Optional pinned SHA-256 digest of the model weights.
#' @param port Optional integer container port. Defaults to `11434L` (Ollama),
#'   `8080L` (llama.cpp), or `8000L` (vLLM).
#' @param host_bind Character scalar host interface binding when publishing a
#'   loopback port; defaults to `"127.0.0.1"`.
#' @param socket_path Optional local host path for a Unix domain socket bind
#'   mount used with `--network none`.
#' @param gpu Character scalar GPU passthrough mode: `"none"`, `"nvidia"`, or
#'   `"rocm"`.
#' @param gpu_devices Character scalar specifying NVIDIA GPU devices (e.g.,
#'   `"all"` or `"device=0"`). Ignored unless `gpu = "nvidia"`.
#' @param memory_limit Optional Docker memory limit string (e.g., `"32g"`).
#' @param cpus Optional positive numeric CPU core limit.
#' @param shm_size Optional shared memory size string (e.g., `"4g"`).
#' @param read_only Logical scalar; mount container root filesystem read-only.
#'   Defaults to `TRUE`.
#' @param network_mode Character scalar container network mode. Defaults to
#'   `"none"` (strict airgap). `"internal"` is supported for Compose internal
#'   loopback setups; other modes fail [preflight_isolation_check()].
#' @param cap_drop Character vector of Linux capabilities to drop. Defaults to
#'   `"ALL"`.
#' @param no_new_privileges Logical scalar enforcing
#'   `--security-opt no-new-privileges:true`. Defaults to `TRUE`.
#' @param user Optional non-root `"uid:gid"` string for container execution.
#' @param tmpfs_size Character scalar size limit for writable `/tmp` tmpfs
#'   (mounted `noexec,nosuid`). Defaults to `"512m"`.
#' @param env Named list or named character vector of additional container
#'   environment variables.
#' @param extra_args Character vector of extra backend CLI arguments.
#' @param container_name Optional container name.
#'
#' @return An S3 object of class `"airgap_container_spec"` containing the
#'   normalized specification and its canonical `spec_digest`.
#'
#' @export
#' @examples
#' spec <- airgap_container_spec(
#'   backend = "ollama",
#'   image = "ollama/ollama",
#'   image_digest = paste0("sha256:", strrep("a", 64)),
#'   model_dir = "/srv/models/llama3",
#'   gpu = "nvidia"
#' )
#' print(spec)
airgap_container_spec <- function(
  backend = c("ollama", "llama.cpp", "vllm"),
  image = NULL,
  image_digest = NULL,
  model_dir = "/srv/airgapllm/models",
  model_file = NULL,
  model_digest = NULL,
  port = NULL,
  host_bind = "127.0.0.1",
  socket_path = NULL,
  gpu = c("none", "nvidia", "rocm"),
  gpu_devices = "all",
  memory_limit = NULL,
  cpus = NULL,
  shm_size = NULL,
  read_only = TRUE,
  network_mode = "none",
  cap_drop = "ALL",
  no_new_privileges = TRUE,
  user = NULL,
  tmpfs_size = "512m",
  env = list(),
  extra_args = character(),
  container_name = NULL
) {
  backend <- match.arg(backend)
  gpu <- match.arg(gpu)
  defs <- backend_defaults(backend)

  if (is.null(image)) {
    image <- defs$image
  }
  assert_scalar_string(image, "image")
  assert_no_control_chars(image, "image")

  # Allow embedded image@sha256:... syntax
  if (grepl("@", image, fixed = TRUE)) {
    parts <- strsplit(image, "@", fixed = TRUE)[[1L]]
    if (length(parts) != 2L || !nzchar(parts[1L]) || !nzchar(parts[2L])) {
      cli::cli_abort("Malformed image digest reference in {.arg image}.", class = "airgap_validation_error")
    }
    embedded_digest <- normalize_sha256_digest(parts[2L])
    if (!is.null(image_digest)) {
      norm_arg <- normalize_sha256_digest(image_digest)
      if (!constant_time_equal(embedded_digest, norm_arg)) {
        cli::cli_abort(
          "Digest embedded in {.arg image} does not match {.arg image_digest}.",
          class = "airgap_validation_error"
        )
      }
    }
    image <- parts[1L]
    image_digest <- embedded_digest
  } else if (!is.null(image_digest)) {
    image_digest <- normalize_sha256_digest(image_digest)
  }

  assert_safe_container_image(image, "image")
  assert_safe_host_path(model_dir, "model_dir", forbid_colon = TRUE)
  if (!is.null(model_file)) assert_safe_model_file(model_file, "model_file")
  if (!is.null(model_digest)) model_digest <- normalize_sha256_digest(model_digest)

  if (is.null(port)) {
    port <- defs$port
  } else {
    if (!is.numeric(port) || length(port) != 1L || is.na(port) || port < 1 || port > 65535 || port != floor(port)) {
      cli::cli_abort("{.arg port} must be an integer between 1 and 65535.", class = "airgap_validation_error")
    }
    port <- as.integer(port)
  }

  assert_safe_token(host_bind, "host_bind", "^[A-Za-z0-9.:\\[\\]-]{1,64}$", "an IP address or hostname token")
  if (!is.null(socket_path)) assert_safe_host_path(socket_path, "socket_path", forbid_colon = TRUE)
  assert_safe_token(gpu_devices, "gpu_devices", "^(all|device=[0-9]+(,[0-9]+)*|[0-9]+(,[0-9]+)*)$", "'all' or GPU device selector")
  if (!is.null(memory_limit)) assert_safe_token(memory_limit, "memory_limit", "^[0-9]+(?:\\.[0-9]+)?[bBkKmMgGtT]?$", "a Docker memory limit (e.g., '32g')")
  if (!is.null(cpus)) {
    if (!is.numeric(cpus) || length(cpus) != 1L || is.na(cpus) || !is.finite(cpus) || cpus <= 0) {
      cli::cli_abort("{.arg cpus} must be a positive number.", class = "airgap_validation_error")
    }
  }
  if (!is.null(shm_size)) assert_safe_token(shm_size, "shm_size", "^[0-9]+(?:\\.[0-9]+)?[bBkKmMgGtT]?$", "a Docker size limit (e.g., '4g')")
  assert_scalar_logical(read_only, "read_only")
  assert_safe_token(network_mode, "network_mode", "^[A-Za-z0-9_.-]{1,64}$", "a Docker network mode identifier")
  if (!is.character(cap_drop)) {
    cli::cli_abort("{.arg cap_drop} must be a character vector.", class = "airgap_validation_error")
  }
  for (cap in cap_drop) {
    assert_safe_token(cap, "cap_drop", "^[A-Za-z0-9_]{1,64}$", "a Linux capability name (e.g., 'ALL')")
  }
  assert_scalar_logical(no_new_privileges, "no_new_privileges")
  if (!is.null(user)) assert_safe_token(user, "user", "^[A-Za-z0-9_-]{1,64}(?::[A-Za-z0-9_-]{1,64})?$", "'uid:gid' or username")
  assert_safe_token(tmpfs_size, "tmpfs_size", "^[0-9]+(?:\\.[0-9]+)?[bBkKmMgGtT]?$", "a tmpfs size limit (e.g., '512m')")
  assert_safe_extra_args(extra_args)
  if (!is.null(container_name)) assert_safe_token(container_name, "container_name", "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", "a valid Docker container name")

  # Normalize and strictly sanitize env to named character list
  if (is.character(env) && length(env) > 0L) {
    if (is.null(names(env)) || any(!nzchar(names(env)))) {
      cli::cli_abort("{.arg env} must be a named list or named character vector.", class = "airgap_validation_error")
    }
    env <- as.list(env)
  } else if (is.list(env) && length(env) > 0L) {
    if (is.null(names(env)) || any(!nzchar(names(env)))) {
      cli::cli_abort("{.arg env} must have non-empty names for all entries.", class = "airgap_validation_error")
    }
    env <- lapply(env, as.character)
  } else if (!is.list(env)) {
    cli::cli_abort("{.arg env} must be a named list or named character vector.", class = "airgap_validation_error")
  }
  for (nm in names(env)) {
    assert_safe_env_entry(nm, env[[nm]])
  }

  spec_core <- list(
    backend = backend,
    image = image,
    image_digest = image_digest,
    model_dir = model_dir,
    container_model_dir = defs$container_model_dir,
    model_file = model_file,
    model_digest = model_digest,
    port = port,
    host_bind = host_bind,
    socket_path = socket_path,
    gpu = gpu,
    gpu_devices = gpu_devices,
    memory_limit = memory_limit,
    cpus = cpus,
    shm_size = shm_size,
    read_only = read_only,
    network_mode = network_mode,
    cap_drop = cap_drop,
    no_new_privileges = no_new_privileges,
    user = user,
    tmpfs_size = tmpfs_size,
    env = env,
    extra_args = extra_args,
    container_name = container_name
  )

  spec_core$spec_digest <- sha256_object(spec_core)
  structure(spec_core, class = "airgap_container_spec")
}

#' @export
print.airgap_container_spec <- function(x, ...) {
  cat("<airgap_container_spec>\n")
  cat("  Backend:       ", x$backend, "\n", sep = "")
  img_ref <- if (is.null(x$image_digest)) {
    paste0(x$image, " [UNPINNED]")
  } else {
    paste0(x$image, "@", substr(x$image_digest, 1L, 19L), "...")
  }
  cat("  Image:         ", img_ref, "\n", sep = "")
  cat("  Network mode:  ", x$network_mode, "\n", sep = "")
  cat("  Read-only:     ", x$read_only, " | Cap-drop: ",
      paste(x$cap_drop, collapse = ","), "\n", sep = "")
  cat("  Model mount:   ", x$model_dir, " -> ", x$container_model_dir, ":ro\n", sep = "")
  if (!is.null(x$model_file)) {
    cat("  Model file:    ", x$model_file, "\n", sep = "")
  }
  cat("  GPU:           ", x$gpu,
      if (identical(x$gpu, "nvidia")) paste0(" (", x$gpu_devices, ")") else "",
      "\n", sep = "")
  cat("  Spec digest:   ", x$spec_digest, "\n", sep = "")
  invisible(x)
}

#' Build mandatory offline environment variables merged with user env
#' @noRd
build_container_env <- function(spec) {
  base_env <- list(
    HF_HUB_OFFLINE = "1",
    TRANSFORMERS_OFFLINE = "1",
    HF_DATASETS_OFFLINE = "1",
    DO_NOT_TRACK = "1"
  )
  if (identical(spec$backend, "ollama")) {
    base_env$OLLAMA_MODELS <- spec$container_model_dir
    base_env$OLLAMA_HOST <- paste0("127.0.0.1:", spec$port)
    base_env$OLLAMA_NOHISTORY <- "1"
  }
  if (length(spec$env) > 0L) {
    for (nm in names(spec$env)) {
      assert_safe_env_entry(nm, as.character(spec$env[[nm]])[1L])
      base_env[[nm]] <- as.character(spec$env[[nm]])[1L]
    }
  }
  base_env[order(names(base_env))]
}

#' Build backend-specific container command arguments
#' @noRd
build_backend_cmd <- function(spec) {
  model_arg <- if (!is.null(spec$model_file)) {
    file.path(spec$container_model_dir, spec$model_file)
  } else {
    spec$container_model_dir
  }
  cmd <- switch(
    spec$backend,
    "ollama" = c("serve"),
    "llama.cpp" = c(
      "--model", model_arg,
      "--host", "127.0.0.1",
      "--port", as.character(spec$port)
    ),
    "vllm" = c(
      "--model", model_arg,
      "--host", "127.0.0.1",
      "--port", as.character(spec$port),
      "--disable-log-requests"
    )
  )
  c(cmd, spec$extra_args)
}

#' Resolve pinned image reference string
#' @noRd
pinned_image_ref <- function(spec, require_pinned = TRUE) {
  if (is.null(spec$image_digest)) {
    if (isTRUE(require_pinned)) {
      cli::cli_abort(
        c(
          "Container image must be pinned with a SHA-256 digest before emitting runtime configs.",
          "i" = "Supply `image_digest = 'sha256:...'` in `airgap_container_spec()`."
        ),
        class = "airgap_security_error"
      )
    }
    return(spec$image)
  }
  paste0(spec$image, "@", spec$image_digest)
}

#' Emit a Hardened `docker run` Command
#'
#' Generates a reproducible, POSIX-quoted `docker run` command (or argument
#' vector) enforcing network isolation (`--network none`), read-only root
#' filesystem, dropped Linux capabilities, offline environment flags, pinned
#' image digest, and read-only local model directory mount.
#'
#' @param spec An [airgap_container_spec()] object.
#' @param file Optional file path to write an executable bash launcher script.
#' @param detach Logical scalar; include `-d` (detached mode). Defaults to
#'   `FALSE`.
#' @param rm Logical scalar; include `--rm` to discard ephemeral container
#'   state on exit. Defaults to `TRUE`.
#' @param format Character scalar: `"shell"` returns a formatted shell command
#'   string; `"args"` returns a character vector of arguments suitable for
#'   `processx::run("docker", args)`.
#' @param require_pinned Logical scalar; abort if `spec$image_digest` is
#'   missing. Defaults to `TRUE`.
#'
#' @return A character scalar (`format = "shell"`) or character vector
#'   (`format = "args"`).
#'
#' @export
#' @examples
#' spec <- airgap_container_spec(
#'   backend = "llama.cpp",
#'   image_digest = paste0("sha256:", strrep("b", 64)),
#'   model_dir = "/srv/models",
#'   model_file = "llama-3.1-8b-q4_K_M.gguf",
#'   gpu = "nvidia"
#' )
#' cat(emit_docker_run(spec))
emit_docker_run <- function(
  spec,
  file = NULL,
  detach = FALSE,
  rm = TRUE,
  format = c("shell", "args"),
  require_pinned = TRUE
) {
  if (!inherits(spec, "airgap_container_spec")) {
    cli::cli_abort("{.arg spec} must be an `airgap_container_spec` object.", class = "airgap_validation_error")
  }
  format <- match.arg(format)
  assert_scalar_logical(detach, "detach")
  assert_scalar_logical(rm, "rm")
  assert_scalar_logical(require_pinned, "require_pinned")

  img_ref <- pinned_image_ref(spec, require_pinned = require_pinned)
  args <- c("run")

  if (rm) args <- c(args, "--rm")
  if (detach) args <- c(args, "-d")
  if (!is.null(spec$container_name)) args <- c(args, "--name", spec$container_name)

  # Isolation & hardening flags
  args <- c(args, "--network", spec$network_mode)
  if (isTRUE(spec$read_only)) args <- c(args, "--read-only")
  for (cap in spec$cap_drop) {
    args <- c(args, "--cap-drop", cap)
  }
  if (isTRUE(spec$no_new_privileges)) {
    args <- c(args, "--security-opt", "no-new-privileges:true")
  }

  # Ephemeral non-executable tmpfs mounts
  args <- c(args, "--tmpfs", paste0("/tmp:rw,noexec,nosuid,size=", spec$tmpfs_size))
  args <- c(args, "--tmpfs", "/run:rw,noexec,nosuid,size=64m")

  # Resource & user limits
  if (!is.null(spec$user)) args <- c(args, "--user", spec$user)
  if (!is.null(spec$memory_limit)) args <- c(args, "--memory", spec$memory_limit)
  if (!is.null(spec$cpus)) args <- c(args, "--cpus", as.character(spec$cpus))
  if (!is.null(spec$shm_size)) args <- c(args, "--shm-size", spec$shm_size)

  # GPU passthrough
  if (identical(spec$gpu, "nvidia")) {
    args <- c(args, "--gpus", spec$gpu_devices)
  } else if (identical(spec$gpu, "rocm")) {
    args <- c(args, "--device", "/dev/kfd", "--device", "/dev/dri")
  }

  # Read-only model mount & optional unix socket mount
  args <- c(args, "-v", paste0(spec$model_dir, ":", spec$container_model_dir, ":ro"))
  if (!is.null(spec$socket_path)) {
    args <- c(args, "-v", paste0(spec$socket_path, ":/run/airgapllm:rw"))
  }

  # Loopback port publish only when not --network none
  if (!identical(spec$network_mode, "none")) {
    args <- c(args, "-p", paste0(spec$host_bind, ":", spec$port, ":", spec$port))
  }

  # Offline environment variables
  env_vars <- build_container_env(spec)
  for (nm in names(env_vars)) {
    args <- c(args, "-e", paste0(nm, "=", env_vars[[nm]]))
  }

  # Pinned image & backend entrypoint args
  args <- c(args, img_ref, build_backend_cmd(spec))

  if (identical(format, "args")) {
    if (!is.null(file)) {
      cli::cli_abort("{.arg file} is only supported when `format = 'shell'`.", class = "airgap_validation_error")
    }
    return(args)
  }

  quoted <- vapply(args, function(a) {
    if (grepl("^[A-Za-z0-9_./:@=,-]+$", a)) a else sh_quote_posix(a)
  }, character(1L))
  cmd <- paste(c("docker", quoted), collapse = " ")

  if (!is.null(file)) {
    assert_safe_write_target(file, arg = "file")
    script <- paste(
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      paste0("# Generated by airgapllm ", airgapllm_version()),
      paste0("# Spec digest: ", spec$spec_digest),
      cmd,
      sep = "\n"
    )
    writeLines(script, con = file, useBytes = TRUE)
  }

  cmd
}

#' Emit a Hardened Docker Compose YAML Configuration
#'
#' Generates a Docker Compose specification enforcing read-only root
#' filesystems, dropped capabilities, `no-new-privileges`, pinned image
#' digests, offline environment variables, read-only model volume mounts, and
#' air-gapped networking (`network_mode: none` or an `internal: true` network).
#'
#' @param spec An [airgap_container_spec()] object.
#' @param file Optional file path to write the Compose YAML.
#' @param service_name Optional Compose service name. Defaults to
#'   `paste0("airgap-", gsub("[^a-z0-9]+", "-", spec$backend))`.
#' @param require_pinned Logical scalar; abort if `spec$image_digest` is
#'   missing. Defaults to `TRUE`.
#'
#' @return A character scalar containing valid Docker Compose YAML.
#'
#' @export
#' @examples
#' spec <- airgap_container_spec(
#'   backend = "vllm",
#'   image_digest = paste0("sha256:", strrep("c", 64)),
#'   model_dir = "/srv/models",
#'   model_file = "qwen2.5-7b-instruct",
#'   gpu = "nvidia"
#' )
#' cat(emit_docker_compose(spec))
emit_docker_compose <- function(
  spec,
  file = NULL,
  service_name = NULL,
  require_pinned = TRUE
) {
  if (!inherits(spec, "airgap_container_spec")) {
    cli::cli_abort("{.arg spec} must be an `airgap_container_spec` object.", class = "airgap_validation_error")
  }
  assert_scalar_logical(require_pinned, "require_pinned")
  img_ref <- pinned_image_ref(spec, require_pinned = require_pinned)

  if (is.null(service_name)) {
    service_name <- paste0("airgap-", gsub("[^a-z0-9]+", "-", tolower(spec$backend)))
  }
  assert_safe_token(service_name, "service_name", "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", "a valid Compose service name")

  volumes <- list(paste0(spec$model_dir, ":", spec$container_model_dir, ":ro"))
  if (!is.null(spec$socket_path)) {
    volumes <- c(volumes, list(paste0(spec$socket_path, ":/run/airgapllm:rw")))
  }

  service <- list(
    image = img_ref,
    read_only = isTRUE(spec$read_only),
    cap_drop = as.list(spec$cap_drop),
    security_opt = if (isTRUE(spec$no_new_privileges)) list("no-new-privileges:true") else list(),
    tmpfs = list(
      paste0("/tmp:rw,noexec,nosuid,size=", spec$tmpfs_size),
      "/run:rw,noexec,nosuid,size=64m"
    ),
    volumes = volumes,
    environment = build_container_env(spec),
    command = as.list(build_backend_cmd(spec)),
    restart = "no"
  )

  if (!is.null(spec$container_name)) service$container_name <- spec$container_name
  if (!is.null(spec$user)) service$user <- spec$user
  if (!is.null(spec$shm_size)) service$shm_size <- spec$shm_size
  if (!is.null(spec$memory_limit)) service$mem_limit <- spec$memory_limit
  if (!is.null(spec$cpus)) service$cpus <- spec$cpus

  if (identical(spec$gpu, "nvidia")) {
    gpu_res <- list(
      driver = "nvidia",
      capabilities = list("gpu")
    )
    if (identical(spec$gpu_devices, "all")) {
      gpu_res$count <- "all"
    } else {
      gpu_res$device_ids <- as.list(strsplit(sub("^device=", "", spec$gpu_devices), ",", fixed = TRUE)[[1L]])
    }
    service$deploy <- list(
      resources = list(
        reservations = list(
          devices = list(gpu_res)
        )
      )
    )
  } else if (identical(spec$gpu, "rocm")) {
    service$devices <- list("/dev/kfd", "/dev/dri")
  }

  compose <- list(services = stats::setNames(list(service), service_name))

  if (identical(spec$network_mode, "internal")) {
    compose$services[[service_name]]$networks <- list("airgap_internal")
    compose$services[[service_name]]$ports <- list(
      paste0(spec$host_bind, ":", spec$port, ":", spec$port)
    )
    compose$networks <- list(
      airgap_internal = list(
        driver = "bridge",
        internal = TRUE
      )
    )
  } else {
    compose$services[[service_name]]$network_mode <- spec$network_mode
  }

  header <- paste0(
    "# Generated by airgapllm ", airgapllm_version(), "\n",
    "# Spec digest: ", spec$spec_digest, "\n"
  )
  yaml_str <- paste0(header, yaml::as.yaml(compose, indent.mapping.sequence = TRUE))

  if (!is.null(file)) {
    assert_safe_write_target(file, arg = "file")
    writeLines(yaml_str, con = file, useBytes = TRUE)
  }

  yaml_str
}

#' Emit an HPC Apptainer Definition File (`.def`)
#'
#' Generates a reproducible Apptainer definition recipe pinning the upstream
#' container image by SHA-256 digest, configuring offline environment flags,
#' recording provenance labels, and documenting the air-gapped HPC execution
#' command (`apptainer run --containall --no-home --net --network none`).
#'
#' @param spec An [airgap_container_spec()] object.
#' @param file Optional path to write the `.def` recipe.
#' @param require_pinned Logical scalar; abort if `spec$image_digest` is
#'   missing. Defaults to `TRUE`.
#'
#' @return A character scalar containing the Apptainer `.def` recipe.
#'
#' @export
#' @examples
#' spec <- airgap_container_spec(
#'   backend = "ollama",
#'   image_digest = paste0("sha256:", strrep("d", 64)),
#'   model_dir = "/scratch/lab/models",
#'   gpu = "nvidia"
#' )
#' cat(emit_apptainer_def(spec))
emit_apptainer_def <- function(spec, file = NULL, require_pinned = TRUE) {
  if (!inherits(spec, "airgap_container_spec")) {
    cli::cli_abort("{.arg spec} must be an `airgap_container_spec` object.", class = "airgap_validation_error")
  }
  assert_scalar_logical(require_pinned, "require_pinned")
  img_ref <- pinned_image_ref(spec, require_pinned = require_pinned)

  env_vars <- build_container_env(spec)
  env_lines <- vapply(
    names(env_vars),
    function(nm) paste0("    export ", nm, "=", sh_quote_posix(env_vars[[nm]])),
    character(1L)
  )

  gpu_flag <- switch(
    spec$gpu,
    "nvidia" = " --nv",
    "rocm" = " --rocm",
    "none" = ""
  )

  quoted_cmd <- vapply(build_backend_cmd(spec), sh_quote_posix, character(1L))
  backend_exec <- switch(
    spec$backend,
    "ollama" = paste(c("exec ollama", quoted_cmd, '"$@"'), collapse = " "),
    "llama.cpp" = paste(c("exec llama-server", quoted_cmd, '"$@"'), collapse = " "),
    "vllm" = paste(c("exec vllm serve", quoted_cmd, '"$@"'), collapse = " ")
  )

  sif_name <- paste0("airgapllm-", gsub("[^a-z0-9]+", "-", tolower(spec$backend)), ".sif")
  run_hint <- paste0(
    "# Air-gapped HPC execution command:\n",
    "#   apptainer build ", sif_name, " airgapllm.def\n",
    "#   apptainer run --containall --no-home --net --network none",
    gpu_flag,
    " --bind ", sh_quote_posix(paste0(spec$model_dir, ":", spec$container_model_dir, ":ro")),
    " ", sif_name
  )

  labels <- c(
    paste0("    org.airgapllm.generator airgapllm-", airgapllm_version()),
    paste0("    org.airgapllm.backend ", spec$backend),
    paste0("    org.airgapllm.spec_digest ", spec$spec_digest),
    paste0("    org.airgapllm.network_mode ", spec$network_mode)
  )
  if (!is.null(spec$model_digest)) {
    labels <- c(labels, paste0("    org.airgapllm.model_digest ", spec$model_digest))
  }

  def_text <- paste(
    c(
      paste0("# Generated by airgapllm ", airgapllm_version()),
      run_hint,
      "",
      "Bootstrap: docker",
      paste0("From: ", img_ref),
      "",
      "%labels",
      labels,
      "",
      "%environment",
      env_lines,
      "",
      "%post",
      paste0("    mkdir -p ", spec$container_model_dir),
      "    chmod 755 /models || true",
      "",
      "%runscript",
      paste0("    ", backend_exec)
    ),
    collapse = "\n"
  )

  if (!is.null(file)) {
    assert_safe_write_target(file, arg = "file")
    writeLines(def_text, con = file, useBytes = TRUE)
  }

  def_text
}

#' Stream SHA-256 Digest of a Local File
#' @noRd
sha256_file_stream <- function(path) {
  con <- file(path, open = "rb")
  on.exit(try(close(con), silent = TRUE), add = TRUE)
  paste0("sha256:", hash_to_hex(openssl::sha256(con)))
}

#' Verify SHA-256 Digests of Local Model Weights
#'
#' Computes streaming SHA-256 digests of a local model file (e.g., GGUF or
#' safetensors) or a directory of sharded weight files without loading the
#' weights into memory, and optionally compares against a pinned expected
#' digest.
#'
#' @param path Character scalar path to a local model file or directory of
#'   model files.
#' @param expected_digest Optional expected SHA-256 digest string (for a single
#'   file or directory manifest) or named character vector mapping relative file
#'   paths to SHA-256 digests (for a directory).
#' @param algorithm Hash algorithm; currently `"sha256"`.
#' @param error_on_mismatch Logical scalar; if `TRUE` and verification fails,
#'   aborts with an `airgap_digest_error`. Defaults to `FALSE`.
#' @param root_dir Optional directory path that `path` must remain strictly
#'   confined within (blocks symlink escapes and path traversal).
#' @param allow_symlinks Logical scalar; if `FALSE` (default), rejects any
#'   symbolic links encountered at `path` or inside a model directory.
#'
#' @return An S3 object of class `"airgap_digest_verification"` containing
#'   `path`, `is_directory`, `algorithm`, `actual_digest`, `expected_digest`,
#'   `matched`, `size_bytes`, `files` (tibble), and `verified_at`.
#'
#' @export
#' @examples
#' tmp_model <- tempfile(fileext = ".gguf")
#' writeBin(charToRaw("mock-gguf-weights-v1"), tmp_model)
#' res <- verify_model_digest(tmp_model)
#' verify_model_digest(tmp_model, expected_digest = res$actual_digest)
#' unlink(tmp_model)
verify_model_digest <- function(
  path,
  expected_digest = NULL,
  algorithm = "sha256",
  error_on_mismatch = FALSE,
  root_dir = NULL,
  allow_symlinks = FALSE
) {
  assert_scalar_string(path, "path")
  algorithm <- match.arg(algorithm, choices = "sha256")
  assert_scalar_logical(error_on_mismatch, "error_on_mismatch")
  assert_scalar_logical(allow_symlinks, "allow_symlinks")

  if (!file.exists(path) && !is_symlink_path(path)) {
    cli::cli_abort("Model path does not exist: {.path {path}}.", class = "airgap_digest_error")
  }

  # Enforce path traversal & symlink containment BEFORE opening any bytes
  assert_path_confined(path, root_dir = root_dir, allow_symlinks = allow_symlinks)
  if (!file.exists(path)) {
    cli::cli_abort("Model path does not exist: {.path {path}}.", class = "airgap_digest_error")
  }

  is_dir <- dir.exists(path)
  norm_path <- normalizePath(path, winslash = "/", mustWork = TRUE)

  if (!is_dir) {
    actual_digest <- sha256_file_stream(norm_path)
    sz <- as.numeric(file.info(norm_path)$size)
    exp_norm <- if (!is.null(expected_digest)) normalize_sha256_digest(expected_digest) else NULL
    matched <- if (is.null(exp_norm)) NA else constant_time_equal(actual_digest, exp_norm)
    files_tbl <- tibble::tibble(
      file = basename(norm_path),
      size_bytes = sz,
      actual_digest = actual_digest,
      expected_digest = if (is.null(exp_norm)) NA_character_ else exp_norm,
      matched = matched
    )
  } else {
    # Inspect ALL directory entries including hidden dotfiles and hidden symlinks before hashing
    raw_entries <- sort(list.files(norm_path, recursive = TRUE, all.files = TRUE, no.. = TRUE, include.dirs = TRUE))
    for (ent in raw_entries) {
      assert_path_confined(file.path(norm_path, ent), root_dir = norm_path, allow_symlinks = allow_symlinks)
    }

    rel_files <- sort(list.files(norm_path, recursive = TRUE, all.files = TRUE, no.. = TRUE, include.dirs = FALSE))
    if (length(rel_files) == 0L) {
      cli::cli_abort("Model directory contains no files: {.path {path}}.", class = "airgap_digest_error")
    }
    full_files <- file.path(norm_path, rel_files)
    for (ff in full_files) {
      assert_path_confined(ff, root_dir = norm_path, allow_symlinks = allow_symlinks)
    }
    file_digests <- vapply(full_files, sha256_file_stream, character(1L))
    file_sizes <- as.numeric(file.info(full_files)$size)
    sz <- sum(file_sizes)

    # Deterministic directory manifest hash over sorted relative paths + SHA-256 digests
    manifest_lines <- paste0(rel_files, "\t", file_digests)
    actual_digest <- sha256_string(paste(manifest_lines, collapse = "\n"))

    if (is.null(expected_digest)) {
      exp_norm <- NULL
      file_exp <- rep(NA_character_, length(rel_files))
      file_matched <- rep(NA, length(rel_files))
      matched <- NA
    } else if (!is.null(names(expected_digest)) && length(expected_digest) >= 1L) {
      exp_norm <- vapply(expected_digest, normalize_sha256_digest, character(1L))
      file_exp <- unname(exp_norm[rel_files])
      file_matched <- vapply(seq_along(rel_files), function(k) {
        !is.na(file_exp[k]) && constant_time_equal(file_digests[k], file_exp[k])
      }, logical(1L))
      missing_expected <- setdiff(names(exp_norm), rel_files)
      extra_files <- setdiff(rel_files, names(exp_norm))
      matched <- all(file_matched) && length(missing_expected) == 0L && length(extra_files) == 0L
    } else {
      exp_norm <- normalize_sha256_digest(expected_digest)
      file_exp <- rep(NA_character_, length(rel_files))
      file_matched <- rep(NA, length(rel_files))
      matched <- constant_time_equal(actual_digest, exp_norm)
    }

    files_tbl <- tibble::tibble(
      file = rel_files,
      size_bytes = file_sizes,
      actual_digest = unname(file_digests),
      expected_digest = as.character(file_exp),
      matched = as.logical(file_matched)
    )
  }

  out <- structure(
    list(
      path = norm_path,
      is_directory = is_dir,
      algorithm = algorithm,
      actual_digest = actual_digest,
      expected_digest = exp_norm,
      matched = matched,
      size_bytes = sz,
      files = files_tbl,
      verified_at = utc_timestamp()
    ),
    class = "airgap_digest_verification"
  )

  if (isTRUE(error_on_mismatch) && isFALSE(matched)) {
    cli::cli_abort(
      c(
        "Model weight SHA-256 verification FAILED for {.path {path}}.",
        "x" = "Expected: {if (length(exp_norm) == 1L) exp_norm else '<per-file manifest>'}",
        "x" = "Actual:   {actual_digest}"
      ),
      class = "airgap_digest_error"
    )
  }

  out
}

#' @export
print.airgap_digest_verification <- function(x, ...) {
  status <- if (is.na(x$matched)) "COMPUTED" else if (isTRUE(x$matched)) "MATCHED" else "MISMATCH"
  cat("<airgap_digest_verification> [", status, "]\n", sep = "")
  cat("  Path:       ", x$path, if (x$is_directory) " (directory)" else "", "\n", sep = "")
  cat("  Size bytes: ", format(x$size_bytes, scientific = FALSE), "\n", sep = "")
  cat("  Actual:     ", x$actual_digest, "\n", sep = "")
  if (!is.null(x$expected_digest) && length(x$expected_digest) == 1L) {
    cat("  Expected:   ", x$expected_digest, "\n", sep = "")
  }
  invisible(x)
}

#' Classify and Validate Whether an Endpoint Is Strictly Local / Loopback
#'
#' Strictly parses a runtime endpoint URL and verifies that it targets only the
#' local loopback interface (`127.0.0.1`, `localhost`, or `[::1]`), a local
#' Unix domain socket (`unix:///...`), or the built-in offline mock runtime
#' (`mock://offline`). Remote hosts, LAN IP addresses, wildcard binds
#' (`0.0.0.0`), userinfo spoofing (`http://127.0.0.1@evil.com`), and
#' unsupported schemes are rejected.
#'
#' @param endpoint Character scalar URL or an `airgap_runtime` object.
#'
#' @return Logical scalar `TRUE` if the endpoint is strictly local/loopback,
#'   `FALSE` otherwise.
#'
#' @export
#' @examples
#' is_loopback_endpoint("http://127.0.0.1:11434")
#' is_loopback_endpoint("http://localhost:8000/v1")
#' is_loopback_endpoint("https://api.openai.com/v1")
is_loopback_endpoint <- function(endpoint) {
  info <- classify_endpoint(endpoint)
  isTRUE(info$allowed)
}

#' Internal strict endpoint parser delegating to centralized SSRF guard
#' @noRd
classify_endpoint <- function(endpoint) {
  classify_endpoint_strict(endpoint)
}

#' Run Pre-Flight Air-Gap Isolation and Integrity Verification
#'
#' Validates container hardening posture (`--network none`, `--read-only`,
#' `--cap-drop ALL`, `no-new-privileges`, pinned image SHA-256 digest, loopback
#' host binding), confirms that any runtime endpoint is strictly loopback /
#' local Unix socket / offline mock, optionally verifies local model weight
#' SHA-256 digests on disk, checks outbound proxy environment variables, and
#' returns a cryptographically hashed (and optionally HMAC-signed) pre-flight
#' verification record.
#'
#' @param spec Optional [airgap_container_spec()] object.
#' @param endpoint Optional character URL or `airgap_runtime` object.
#' @param model_path Optional local path to model weights to verify on disk.
#' @param expected_model_digest Optional expected SHA-256 digest for
#'   `model_path`. Defaults to `spec$model_digest` when available.
#' @param allow_internal_network Logical scalar; if `FALSE` (default),
#'   requires `spec$network_mode == "none"`. If `TRUE`, also permits
#'   `network_mode == "internal"` when `host_bind` is strictly loopback.
#' @param check_proxies Logical scalar; inspect outbound proxy environment
#'   variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`,
#'   `SOCKS_PROXY`, case-insensitive). Defaults to `TRUE`.
#' @param strict_proxy Logical scalar; if `TRUE` (default), active outbound
#'   proxy variables without explicit `127.0.0.1` and `localhost` entries in
#'   `NO_PROXY` cause pre-flight verification to fail closed. Set to `FALSE` to
#'   downgrade proxy exposure to an advisory warning.
#' @param allow_symlinks Logical scalar passed to [verify_model_digest()] when
#'   verifying `model_path`. Defaults to `FALSE`.
#' @param signing_key Optional secret key (character or raw) to attach an
#'   HMAC-SHA256 attestation signature to the verification record.
#' @param error_on_fail Logical scalar; if `TRUE`, aborts with an
#'   `airgap_isolation_error` when any required check fails. Defaults to
#'   `FALSE`.
#'
#' @return An S3 object of class `"airgap_preflight"` with `passed`, `status`,
#'   `checks` (tibble), `spec_digest`, `model_digest`, `endpoint_class`,
#'   `checked_at`, `record_hash`, and `signature`.
#'
#' @export
#' @examples
#' spec <- airgap_container_spec(
#'   backend = "ollama",
#'   image_digest = paste0("sha256:", strrep("a", 64)),
#'   model_dir = "/srv/models"
#' )
#' pf <- preflight_isolation_check(spec = spec, endpoint = "http://127.0.0.1:11434")
#' pf$passed
preflight_isolation_check <- function(
  spec = NULL,
  endpoint = NULL,
  model_path = NULL,
  expected_model_digest = NULL,
  allow_internal_network = FALSE,
  check_proxies = TRUE,
  strict_proxy = TRUE,
  allow_symlinks = FALSE,
  signing_key = NULL,
  error_on_fail = FALSE
) {
  assert_scalar_logical(allow_internal_network, "allow_internal_network")
  assert_scalar_logical(check_proxies, "check_proxies")
  assert_scalar_logical(strict_proxy, "strict_proxy")
  assert_scalar_logical(allow_symlinks, "allow_symlinks")
  assert_scalar_logical(error_on_fail, "error_on_fail")

  if (!is.null(spec) && !inherits(spec, "airgap_container_spec")) {
    cli::cli_abort("{.arg spec} must be an `airgap_container_spec` object or `NULL`.", class = "airgap_validation_error")
  }
  if (is.null(spec) && is.null(endpoint) && is.null(model_path)) {
    cli::cli_abort(
      "Provide at least one of {.arg spec}, {.arg endpoint}, or {.arg model_path}.",
      class = "airgap_validation_error"
    )
  }

  checks <- list()
  add_check <- function(id, status, severity, detail) {
    checks[[length(checks) + 1L]] <<- list(
      check_id = id,
      status = status,
      severity = severity,
      detail = detail
    )
  }

  spec_digest <- NULL
  model_digest_verified <- NULL
  endpoint_class <- NULL
  endpoint_str <- NULL

  # 1. Container specification security checks
  if (!is.null(spec)) {
    spec_digest <- spec$spec_digest

    # Network isolation
    net_ok <- identical(spec$network_mode, "none") ||
      (isTRUE(allow_internal_network) && identical(spec$network_mode, "internal"))
    add_check(
      "network_isolation",
      if (net_ok) "pass" else "fail",
      "required",
      if (net_ok) {
        paste0("Container network_mode is '", spec$network_mode, "'.")
      } else {
        paste0("Insecure container network_mode '", spec$network_mode, "' (expected 'none').")
      }
    )

    # Read-only rootfs
    add_check(
      "read_only_rootfs",
      if (isTRUE(spec$read_only)) "pass" else "fail",
      "required",
      if (isTRUE(spec$read_only)) {
        "Container root filesystem is read-only."
      } else {
        "Container root filesystem is writable (read_only = FALSE)."
      }
    )

    # Capabilities dropped
    caps_ok <- "ALL" %in% toupper(spec$cap_drop)
    add_check(
      "capabilities_dropped",
      if (caps_ok) "pass" else "fail",
      "required",
      if (caps_ok) {
        "All Linux capabilities dropped (--cap-drop ALL)."
      } else {
        "Linux capabilities not fully dropped (missing 'ALL' in cap_drop)."
      }
    )

    # no-new-privileges
    add_check(
      "no_new_privileges",
      if (isTRUE(spec$no_new_privileges)) "pass" else "fail",
      "required",
      if (isTRUE(spec$no_new_privileges)) {
        "no-new-privileges security option enabled."
      } else {
        "no-new-privileges security option disabled."
      }
    )

    # Image digest pinned
    pin_ok <- is_valid_sha256_digest(spec$image_digest)
    add_check(
      "image_digest_pinned",
      if (pin_ok) "pass" else "fail",
      "required",
      if (pin_ok) {
        paste0("Image pinned to ", spec$image_digest, ".")
      } else {
        "Container image is missing a valid pinned SHA-256 digest."
      }
    )

    # Host bind loopback
    bind_ok <- tolower(trimws(spec$host_bind)) %in% c("127.0.0.1", "localhost", "::1")
    add_check(
      "host_bind_loopback",
      if (bind_ok) "pass" else "fail",
      "required",
      if (bind_ok) {
        paste0("Host bind interface restricted to loopback (", spec$host_bind, ").")
      } else {
        paste0("Non-loopback host_bind rejected: '", spec$host_bind, "'.")
      }
    )

    # Container environment isolation (no overrides of offline flags, OLLAMA_HOST, or *_PROXY)
    bad_env_names <- if (length(spec$env) > 0L && !is.null(names(spec$env))) {
      names(spec$env)[vapply(names(spec$env), is_forbidden_container_env, logical(1L))]
    } else {
      character()
    }
    env_ok <- length(bad_env_names) == 0L
    add_check(
      "container_env_isolation",
      if (env_ok) "pass" else "fail",
      "required",
      if (env_ok) {
        "Container environment preserves mandatory offline/loopback flags with no proxy overrides."
      } else {
        paste0("Disallowed container env override(s) detected: ", paste(bad_env_names, collapse = ", "), ".")
      }
    )
  }

  # 2. Endpoint loopback / local-only check
  endpoint_host <- NULL
  if (!is.null(endpoint)) {
    endpoint_str <- if (inherits(endpoint, "airgap_runtime")) endpoint$endpoint else as.character(endpoint)[1L]
    ep_info <- classify_endpoint(endpoint)
    endpoint_class <- ep_info$endpoint_class
    endpoint_host <- ep_info$host
    add_check(
      "endpoint_loopback_only",
      if (isTRUE(ep_info$allowed)) "pass" else "fail",
      "required",
      ep_info$reason
    )
  }

  # 3. Model weight SHA-256 verification (with symlink & model_dir confinement)
  exp_model <- expected_model_digest %||% (if (!is.null(spec)) spec$model_digest else NULL)
  eff_root <- if (!is.null(spec) && dir.exists(spec$model_dir)) spec$model_dir else NULL
  if (!is.null(model_path)) {
    if (!file.exists(model_path) && !is_symlink_path(model_path)) {
      add_check(
        "model_digest_verified",
        "fail",
        "required",
        paste0("Model path does not exist: ", model_path)
      )
    } else {
      ver <- tryCatch(
        verify_model_digest(
          model_path,
          expected_digest = exp_model,
          error_on_mismatch = FALSE,
          root_dir = eff_root,
          allow_symlinks = allow_symlinks
        ),
        error = function(e) structure(list(message = conditionMessage(e)), class = "airgap_pf_err")
      )
      if (inherits(ver, "airgap_pf_err")) {
        add_check("model_digest_verified", "fail", "required", ver$message)
      } else if (is.null(exp_model)) {
        model_digest_verified <- ver$actual_digest
        add_check(
          "model_digest_verified",
          "fail",
          "required",
          "Model weights found on disk, but no expected SHA-256 digest was pinned for verification."
        )
      } else {
        model_digest_verified <- ver$actual_digest
        add_check(
          "model_digest_verified",
          if (isTRUE(ver$matched)) "pass" else "fail",
          "required",
          if (isTRUE(ver$matched)) {
            paste0("Model weights verified against pinned SHA-256 (", ver$actual_digest, ").")
          } else {
            paste0("Model weight SHA-256 MISMATCH (actual: ", ver$actual_digest, ").")
          }
        )
      }
    }
  } else if (!is.null(exp_model)) {
    pin_m <- is_valid_sha256_digest(exp_model)
    model_digest_verified <- if (pin_m) normalize_sha256_digest(exp_model) else NULL
    add_check(
      "model_digest_pinned",
      if (pin_m) "pass" else "fail",
      "required",
      if (pin_m) {
        paste0("Model digest pinned in configuration (", model_digest_verified, "); pass `model_path` to verify file bytes.")
      } else {
        "Invalid expected_model_digest format."
      }
    )
  }

  # 4. Outbound proxy environment variable audit (case-insensitive; fails closed when strict_proxy = TRUE)
  if (isTRUE(check_proxies)) {
    prox <- detect_outbound_proxies(endpoint_host = endpoint_host)
    if (length(prox$active_vars) == 0L) {
      add_check("env_proxy_isolation", "pass", "required", "No outbound proxy environment variables detected.")
    } else if (isTRUE(prox$has_local_bypass)) {
      add_check(
        "env_proxy_isolation",
        "pass",
        "required",
        paste0("Proxy variables set (", paste(prox$active_vars, collapse = ", "), "), with required loopback host(s) explicitly in NO_PROXY; HTTP runtimes also force noproxy='*'.")
      )
    } else {
      req_hosts <- if (isTRUE(prox$needs_ipv6)) "127.0.0.1, localhost, and ::1" else "127.0.0.1 and localhost"
      add_check(
        "env_proxy_isolation",
        if (isTRUE(strict_proxy)) "fail" else "warn",
        if (isTRUE(strict_proxy)) "required" else "advisory",
        paste0(
          "Outbound proxy variable(s) active (", paste(prox$active_vars, collapse = ", "),
          ") without explicit ", req_hosts, " bypass in NO_PROXY."
        )
      )
    }
  }

  checks_tbl <- tibble::tibble(
    check_id = vapply(checks, `[[`, character(1L), "check_id"),
    status = vapply(checks, `[[`, character(1L), "status"),
    severity = vapply(checks, `[[`, character(1L), "severity"),
    detail = vapply(checks, `[[`, character(1L), "detail")
  )

  required_failed <- any(checks_tbl$severity == "required" & checks_tbl$status == "fail")
  passed <- !required_failed
  status <- if (passed) "PASS" else "FAIL"
  checked_at <- utc_timestamp()

  payload <- list(
    status = status,
    passed = passed,
    spec_digest = spec_digest,
    model_digest = model_digest_verified,
    endpoint_class = endpoint_class,
    checked_at = checked_at,
    checks = lapply(checks, function(x) x)
  )
  record_hash <- sha256_object(payload)
  signature <- if (!is.null(signing_key)) {
    paste0("hmac-sha256:", hmac_sha256_hex(canonical_json(payload), signing_key))
  } else {
    NULL
  }

  result <- structure(
    list(
      passed = passed,
      status = status,
      checks = checks_tbl,
      spec_digest = spec_digest,
      model_digest = model_digest_verified,
      endpoint = endpoint_str,
      endpoint_class = endpoint_class,
      checked_at = checked_at,
      record_hash = record_hash,
      signature = signature
    ),
    class = "airgap_preflight"
  )

  if (isTRUE(error_on_fail) && !passed) {
    failed_rows <- checks_tbl[checks_tbl$severity == "required" & checks_tbl$status == "fail", , drop = FALSE]
    bullets <- stats::setNames(
      escape_cli_braces(paste0(failed_rows$check_id, ": ", failed_rows$detail)),
      rep("x", nrow(failed_rows))
    )
    cli::cli_abort(
      c("Air-gap pre-flight isolation check FAILED.", bullets),
      class = "airgap_isolation_error"
    )
  }

  result
}

#' @export
print.airgap_preflight <- function(x, ...) {
  cat("<airgap_preflight> [", x$status, "]\n", sep = "")
  cat("  Checked at:   ", x$checked_at, "\n", sep = "")
  if (!is.null(x$endpoint_class)) {
    cat("  Endpoint:     ", x$endpoint_class, "\n", sep = "")
  }
  cat("  Record hash:  ", x$record_hash, "\n", sep = "")
  if (!is.null(x$signature)) {
    cat("  Signature:    ", substr(x$signature, 1L, 32L), "...\n", sep = "")
  }
  for (i in seq_len(nrow(x$checks))) {
    row <- x$checks[i, , drop = FALSE]
    tag <- toupper(row$status)
    cat("  [", tag, "] ", row$check_id, ": ", row$detail, "\n", sep = "")
  }
  invisible(x)
}
