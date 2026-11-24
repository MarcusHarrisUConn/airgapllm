# Emit a Hardened `docker run` Command

Generates a reproducible, POSIX-quoted `docker run` command (or argument
vector) enforcing network isolation (`--network none`), read-only root
filesystem, dropped Linux capabilities, offline environment flags,
pinned image digest, and read-only local model directory mount.

## Usage

``` r
emit_docker_run(
  spec,
  file = NULL,
  detach = FALSE,
  rm = TRUE,
  format = c("shell", "args"),
  require_pinned = TRUE
)
```

## Arguments

- spec:

  An
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md)
  object.

- file:

  Optional file path to write an executable bash launcher script.

- detach:

  Logical scalar; include `-d` (detached mode). Defaults to `FALSE`.

- rm:

  Logical scalar; include `--rm` to discard ephemeral container state on
  exit. Defaults to `TRUE`.

- format:

  Character scalar: `"shell"` returns a formatted shell command string;
  `"args"` returns a character vector of arguments suitable for
  `processx::run("docker", args)`.

- require_pinned:

  Logical scalar; abort if `spec$image_digest` is missing. Defaults to
  `TRUE`.

## Value

A character scalar (`format = "shell"`) or character vector
(`format = "args"`).

## Examples

``` r
spec <- airgap_container_spec(
  backend = "llama.cpp",
  image_digest = paste0("sha256:", strrep("b", 64)),
  model_dir = "/srv/models",
  model_file = "llama-3.1-8b-q4_K_M.gguf",
  gpu = "nvidia"
)
cat(emit_docker_run(spec))
#> docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:rw,noexec,nosuid,size=512m --tmpfs /run:rw,noexec,nosuid,size=64m --gpus all -v /srv/models:/models:ro -e DO_NOT_TRACK=1 -e HF_DATASETS_OFFLINE=1 -e HF_HUB_OFFLINE=1 -e TRANSFORMERS_OFFLINE=1 ghcr.io/ggerganov/llama.cpp@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --model /models/llama-3.1-8b-q4_K_M.gguf --host 127.0.0.1 --port 8080
```
