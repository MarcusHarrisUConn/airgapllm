test_that("airgap_container_spec creates hardened specs for all backends", {
  dig <- paste0("sha256:", strrep("a", 64))

  s_ollama <- airgap_container_spec(
    backend = "ollama",
    image_digest = dig,
    model_dir = "/srv/models/ollama",
    gpu = "nvidia"
  )
  expect_s3_class(s_ollama, "airgap_container_spec")
  expect_equal(s_ollama$backend, "ollama")
  expect_equal(s_ollama$image, "ollama/ollama")
  expect_equal(s_ollama$image_digest, dig)
  expect_equal(s_ollama$port, 11434L)
  expect_true(s_ollama$read_only)
  expect_equal(s_ollama$network_mode, "none")
  expect_equal(s_ollama$cap_drop, "ALL")
  expect_true(s_ollama$no_new_privileges)
  expect_match(s_ollama$spec_digest, "^sha256:[0-9a-f]{64}$")
  expect_output(print(s_ollama), "airgap_container_spec")

  # Embedded image@sha256:... parsing
  s_embed <- airgap_container_spec(
    backend = "llama.cpp",
    image = paste0("ghcr.io/ggerganov/llama.cpp@", dig),
    model_dir = "/srv/models",
    model_file = "model.gguf"
  )
  expect_equal(s_embed$image, "ghcr.io/ggerganov/llama.cpp")
  expect_equal(s_embed$image_digest, dig)
  expect_equal(s_embed$port, 8080L)

  # Conflicting embedded digest vs image_digest errors
  expect_error(
    airgap_container_spec(
      backend = "vllm",
      image = paste0("vllm/vllm-openai@", dig),
      image_digest = paste0("sha256:", strrep("b", 64))
    ),
    class = "airgap_validation_error"
  )

  # Invalid digest format errors
  expect_error(
    airgap_container_spec(backend = "ollama", image_digest = "sha256:short"),
    class = "airgap_digest_error"
  )

  # Invalid port / cpus errors
  expect_error(
    airgap_container_spec(backend = "ollama", port = 99999L),
    class = "airgap_validation_error"
  )
  expect_error(
    airgap_container_spec(backend = "ollama", cpus = -2),
    class = "airgap_validation_error"
  )
})

test_that("emit_docker_run emits hardened air-gapped CLI commands and scripts", {
  dig <- paste0("sha256:", strrep("b", 64))
  spec <- airgap_container_spec(
    backend = "llama.cpp",
    image_digest = dig,
    model_dir = "/srv/lab models/gguf",
    model_file = "llama-3.1-8b-q4.gguf",
    socket_path = "/run/airgap-sock",
    gpu = "nvidia",
    gpu_devices = "device=0",
    memory_limit = "24g",
    cpus = 8,
    shm_size = "4g",
    user = "1000:1000",
    container_name = "airgap-llama",
    env = list(CUSTOM_FLAG = "1")
  )

  cmd <- emit_docker_run(spec)
  expect_match(cmd, "--network none", fixed = TRUE)
  expect_match(cmd, "--read-only", fixed = TRUE)
  expect_match(cmd, "--cap-drop ALL", fixed = TRUE)
  expect_match(cmd, "--security-opt no-new-privileges:true", fixed = TRUE)
  expect_match(cmd, "--gpus device=0", fixed = TRUE)
  expect_match(cmd, "HF_HUB_OFFLINE=1", fixed = TRUE)
  expect_match(cmd, "TRANSFORMERS_OFFLINE=1", fixed = TRUE)
  expect_match(cmd, "DO_NOT_TRACK=1", fixed = TRUE)
  expect_match(cmd, "CUSTOM_FLAG=1", fixed = TRUE)
  expect_match(cmd, paste0("ghcr.io/ggerganov/llama.cpp@", dig), fixed = TRUE)
  expect_match(cmd, "'/srv/lab models/gguf:/models:ro'", fixed = TRUE)
  expect_match(cmd, "/run/airgap-sock:/run/airgapllm:rw", fixed = TRUE)
  expect_match(cmd, "--model /models/llama-3.1-8b-q4.gguf", fixed = TRUE)

  # Args format for processx
  args <- emit_docker_run(spec, format = "args")
  expect_type(args, "character")
  expect_equal(args[1L], "run")
  expect_true("--network" %in% args)
  expect_true("--read-only" %in% args)

  # ROCm GPU flags
  spec_rocm <- airgap_container_spec(
    backend = "vllm",
    image_digest = dig,
    model_dir = "/srv/models",
    model_file = "qwen2.5-7b",
    gpu = "rocm"
  )
  cmd_rocm <- emit_docker_run(spec_rocm)
  expect_match(cmd_rocm, "--device /dev/kfd --device /dev/dri", fixed = TRUE)
  expect_match(cmd_rocm, "--disable-log-requests", fixed = TRUE)

  # Write script to disk
  script_path <- withr::local_tempfile(fileext = ".sh")
  emit_docker_run(spec, file = script_path)
  lines <- readLines(script_path)
  expect_equal(lines[1L], "#!/usr/bin/env bash")
  expect_true(any(grepl("--network none", lines, fixed = TRUE)))

  # Rejects unpinned image by default
  unpinned <- airgap_container_spec(backend = "ollama")
  expect_error(emit_docker_run(unpinned), class = "airgap_security_error")
})

test_that("emit_docker_compose produces valid hardened YAML for airgap and internal modes", {
  dig <- paste0("sha256:", strrep("c", 64))

  spec_none <- airgap_container_spec(
    backend = "ollama",
    image_digest = dig,
    model_dir = "/srv/models",
    gpu = "nvidia"
  )
  yml_none <- emit_docker_compose(spec_none)
  parsed <- yaml::yaml.load(yml_none)
  svc <- parsed$services[["airgap-ollama"]]
  expect_equal(svc$image, paste0("ollama/ollama@", dig))
  expect_equal(svc$network_mode, "none")
  expect_true(svc$read_only)
  expect_equal(svc$cap_drop, "ALL")
  expect_true("no-new-privileges:true" %in% svc$security_opt)
  expect_true(any(grepl(":/models:ro$", unlist(svc$volumes))))
  expect_equal(svc$deploy$resources$reservations$devices[[1L]]$driver, "nvidia")
  expect_equal(svc$environment$HF_HUB_OFFLINE, "1")
  expect_equal(svc$environment$OLLAMA_NOHISTORY, "1")

  # Internal network mode publishes loopback port only
  spec_int <- airgap_container_spec(
    backend = "vllm",
    image_digest = dig,
    model_dir = "/srv/models",
    network_mode = "internal"
  )
  yml_path <- withr::local_tempfile(fileext = ".yml")
  yml_int <- emit_docker_compose(spec_int, file = yml_path)
  expect_true(file.exists(yml_path))
  parsed_int <- yaml::yaml.load(yml_int)
  expect_true(isTRUE(parsed_int$networks$airgap_internal$internal))
  expect_equal(parsed_int$services[["airgap-vllm"]]$ports[[1L]], "127.0.0.1:8000:8000")
})

test_that("emit_apptainer_def generates valid HPC Apptainer recipes", {
  dig <- paste0("sha256:", strrep("d", 64))
  mod_dig <- paste0("sha256:", strrep("e", 64))
  spec <- airgap_container_spec(
    backend = "vllm",
    image_digest = dig,
    model_dir = "/scratch/hpc/models",
    model_file = "llama-3.1-8b",
    model_digest = mod_dig,
    gpu = "nvidia"
  )

  def_path <- withr::local_tempfile(fileext = ".def")
  def_txt <- emit_apptainer_def(spec, file = def_path)
  expect_true(file.exists(def_path))
  expect_match(def_txt, "Bootstrap: docker", fixed = TRUE)
  expect_match(def_txt, paste0("From: vllm/vllm-openai@", dig), fixed = TRUE)
  expect_match(def_txt, "--containall --no-home --net --network none --nv", fixed = TRUE)
  expect_match(def_txt, paste0("org.airgapllm.model_digest ", mod_dig), fixed = TRUE)
  expect_match(def_txt, "export HF_HUB_OFFLINE='1'", fixed = TRUE)
  expect_match(def_txt, "%runscript", fixed = TRUE)
  expect_match(def_txt, "exec vllm serve", fixed = TRUE)
})

test_that("verify_model_digest verifies single files and sharded directories", {
  tmp_file <- withr::local_tempfile(fileext = ".gguf")
  writeBin(charToRaw("deterministic-model-weights-v1"), tmp_file)

  v_comp <- verify_model_digest(tmp_file)
  expect_s3_class(v_comp, "airgap_digest_verification")
  expect_true(is.na(v_comp$matched))
  expect_match(v_comp$actual_digest, "^sha256:[0-9a-f]{64}$")
  expect_output(print(v_comp), "COMPUTED")

  # Match with and without sha256: prefix, case-insensitive
  raw_hex <- toupper(sub("^sha256:", "", v_comp$actual_digest))
  v_ok <- verify_model_digest(tmp_file, expected_digest = raw_hex)
  expect_true(v_ok$matched)
  expect_output(print(v_ok), "MATCHED")

  # Mismatch detection
  wrong_dig <- paste0("sha256:", strrep("f", 64))
  v_bad <- verify_model_digest(tmp_file, expected_digest = wrong_dig)
  expect_false(v_bad$matched)
  expect_error(
    verify_model_digest(tmp_file, expected_digest = wrong_dig, error_on_mismatch = TRUE),
    class = "airgap_digest_error"
  )

  # Sharded directory manifest verification
  mod_dir <- withr::local_tempdir()
  writeBin(charToRaw("shard-1-bytes"), file.path(mod_dir, "model-00001.safetensors"))
  writeBin(charToRaw("shard-2-bytes"), file.path(mod_dir, "model-00002.safetensors"))
  v_dir <- verify_model_digest(mod_dir)
  expect_true(v_dir$is_directory)
  expect_equal(nrow(v_dir$files), 2L)

  v_dir_ok <- verify_model_digest(mod_dir, expected_digest = v_dir$actual_digest)
  expect_true(v_dir_ok$matched)

  # Named per-file expected vector
  per_file_exp <- stats::setNames(v_dir$files$actual_digest, v_dir$files$file)
  v_per_ok <- verify_model_digest(mod_dir, expected_digest = per_file_exp)
  expect_true(v_per_ok$matched)

  # Tamper one shard -> fails both overall and per-file check
  writeBin(charToRaw("tampered-shard-2"), file.path(mod_dir, "model-00002.safetensors"))
  expect_false(verify_model_digest(mod_dir, expected_digest = v_dir$actual_digest)$matched)
  expect_false(verify_model_digest(mod_dir, expected_digest = per_file_exp)$matched)
})

test_that("is_loopback_endpoint strictly rejects all non-loopback and spoofed URLs", {
  # Allowed local endpoints
  expect_true(is_loopback_endpoint("http://127.0.0.1:11434"))
  expect_true(is_loopback_endpoint("http://localhost:8000/v1"))
  expect_true(is_loopback_endpoint("https://[::1]:8443/v1"))
  expect_true(is_loopback_endpoint("unix:///var/run/airgapllm.sock"))
  expect_true(is_loopback_endpoint("mock://offline"))

  # Rejected remote, LAN, wildcard, spoofing, and invalid endpoints
  bad_urls <- c(
    "https://api.openai.com/v1",
    "https://api.anthropic.com/v1",
    "http://10.0.0.5:11434",
    "http://192.168.1.10:8000",
    "http://172.16.0.2:8000",
    "http://0.0.0.0:11434",
    "http://127.0.0.1@evil.com:11434",
    "http://user:pass@127.0.0.1:11434",
    "http://localhost.evil.com:11434",
    "http://127.0.0.1.nip.io:11434",
    "http://127.1:11434",
    "ftp://127.0.0.1/model",
    "file:///etc/passwd",
    "unix:///tmp/../etc/passwd",
    "http://127.0.0.1:99999",
    "http://127.0.0.1:11434 extra",
    "",
    NA_character_
  )
  for (u in bad_urls) {
    expect_false(is_loopback_endpoint(u), info = paste("Should reject:", u))
  }
})

test_that("preflight_isolation_check verifies hardened posture, model SHA, proxies, and signing", {
  dig <- paste0("sha256:", strrep("1", 64))
  tmp_model <- withr::local_tempfile(fileext = ".gguf")
  writeBin(charToRaw("verified-gguf-payload"), tmp_model)
  mod_sha <- verify_model_digest(tmp_model)$actual_digest

  good_spec <- airgap_container_spec(
    backend = "ollama",
    image_digest = dig,
    model_dir = dirname(tmp_model),
    model_file = basename(tmp_model),
    model_digest = mod_sha
  )

  sig_key <- pii_vault_key()
  pf_ok <- withr::with_envvar(
    c(HTTP_PROXY = "", HTTPS_PROXY = "", ALL_PROXY = "", http_proxy = "", https_proxy = "", all_proxy = ""),
    preflight_isolation_check(
      spec = good_spec,
      endpoint = "http://127.0.0.1:11434",
      model_path = tmp_model,
      signing_key = sig_key
    )
  )
  expect_s3_class(pf_ok, "airgap_preflight")
  expect_true(pf_ok$passed)
  expect_equal(pf_ok$status, "PASS")
  expect_match(pf_ok$record_hash, "^sha256:[0-9a-f]{64}$")
  expect_match(pf_ok$signature, "^hmac-sha256:[0-9a-f]{64}$")
  expect_output(print(pf_ok), "PASS")

  # Outbound proxy fails closed by default (strict_proxy = TRUE), warns when strict_proxy = FALSE
  pf_proxy_strict <- withr::with_envvar(
    c(HTTP_PROXY = "http://corp-proxy:3128", NO_PROXY = "", no_proxy = ""),
    preflight_isolation_check(spec = good_spec, endpoint = "http://127.0.0.1:11434")
  )
  expect_false(pf_proxy_strict$passed)
  proxy_row_s <- pf_proxy_strict$checks[pf_proxy_strict$checks$check_id == "env_proxy_isolation", ]
  expect_equal(proxy_row_s$status, "fail")

  pf_proxy_warn <- withr::with_envvar(
    c(HTTP_PROXY = "http://corp-proxy:3128", NO_PROXY = "", no_proxy = ""),
    preflight_isolation_check(spec = good_spec, endpoint = "http://127.0.0.1:11434", strict_proxy = FALSE)
  )
  expect_true(pf_proxy_warn$passed)
  proxy_row <- pf_proxy_warn$checks[pf_proxy_warn$checks$check_id == "env_proxy_isolation", ]
  expect_equal(proxy_row$status, "warn")

  # Insecure spec checks catch every misconfiguration
  bad_spec <- airgap_container_spec(
    backend = "ollama",
    image_digest = NULL,
    network_mode = "bridge",
    read_only = FALSE,
    cap_drop = character(),
    no_new_privileges = FALSE,
    host_bind = "0.0.0.0"
  )
  pf_bad <- preflight_isolation_check(
    spec = bad_spec,
    endpoint = "https://api.openai.com/v1",
    model_path = tmp_model,
    expected_model_digest = paste0("sha256:", strrep("9", 64))
  )
  expect_false(pf_bad$passed)
  expect_equal(pf_bad$status, "FAIL")
  failed_ids <- pf_bad$checks$check_id[pf_bad$checks$status == "fail"]
  expect_true(all(c(
    "network_isolation",
    "read_only_rootfs",
    "capabilities_dropped",
    "no_new_privileges",
    "image_digest_pinned",
    "host_bind_loopback",
    "endpoint_loopback_only",
    "model_digest_verified"
  ) %in% failed_ids))

  expect_error(
    preflight_isolation_check(spec = bad_spec, error_on_fail = TRUE),
    class = "airgap_isolation_error"
  )
})
