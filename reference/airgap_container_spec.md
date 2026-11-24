# Define a Hardened Air-Gapped Local LLM Container Specification

Creates a validated, digest-pinned container specification for running
local open-weights LLM inference backends (`"ollama"`, `"llama.cpp"`, or
`"vllm"`) under strict network isolation (`--network none`), a read-only
root filesystem, dropped Linux capabilities, and read-only local model
mounts.

## Usage

``` r
airgap_container_spec(
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
)
```

## Arguments

- backend:

  Character scalar selecting the local inference runtime: `"ollama"`,
  `"llama.cpp"`, or `"vllm"`.

- image:

  Character scalar container image name (without tag or digest, or with
  `@sha256:...` embedded). Defaults to the standard upstream image for
  `backend`.

- image_digest:

  Character scalar pinned SHA-256 image digest
  (`"sha256:<64 hex chars>"`), or `NULL` if embedded in `image` or
  deferred for inspection by
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md).

- model_dir:

  Character scalar local host directory containing model weights,
  mounted read-only at `/models` inside the container.

- model_file:

  Optional character scalar filename (relative to `model_dir`) or full
  path to the GGUF/safetensors model weights.

- model_digest:

  Optional pinned SHA-256 digest of the model weights.

- port:

  Optional integer container port. Defaults to `11434L` (Ollama),
  `8080L` (llama.cpp), or `8000L` (vLLM).

- host_bind:

  Character scalar host interface binding when publishing a loopback
  port; defaults to `"127.0.0.1"`.

- socket_path:

  Optional local host path for a Unix domain socket bind mount used with
  `--network none`.

- gpu:

  Character scalar GPU passthrough mode: `"none"`, `"nvidia"`, or
  `"rocm"`.

- gpu_devices:

  Character scalar specifying NVIDIA GPU devices (e.g., `"all"` or
  `"device=0"`). Ignored unless `gpu = "nvidia"`.

- memory_limit:

  Optional Docker memory limit string (e.g., `"32g"`).

- cpus:

  Optional positive numeric CPU core limit.

- shm_size:

  Optional shared memory size string (e.g., `"4g"`).

- read_only:

  Logical scalar; mount container root filesystem read-only. Defaults to
  `TRUE`.

- network_mode:

  Character scalar container network mode. Defaults to `"none"` (strict
  airgap). `"internal"` is supported for Compose internal loopback
  setups; other modes fail
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md).

- cap_drop:

  Character vector of Linux capabilities to drop. Defaults to `"ALL"`.

- no_new_privileges:

  Logical scalar enforcing `--security-opt no-new-privileges:true`.
  Defaults to `TRUE`.

- user:

  Optional non-root `"uid:gid"` string for container execution.

- tmpfs_size:

  Character scalar size limit for writable `/tmp` tmpfs (mounted
  `noexec,nosuid`). Defaults to `"512m"`.

- env:

  Named list or named character vector of additional container
  environment variables.

- extra_args:

  Character vector of extra backend CLI arguments.

- container_name:

  Optional container name.

## Value

An S3 object of class `"airgap_container_spec"` containing the
normalized specification and its canonical `spec_digest`.

## Examples

``` r
spec <- airgap_container_spec(
  backend = "ollama",
  image = "ollama/ollama",
  image_digest = paste0("sha256:", strrep("a", 64)),
  model_dir = "/srv/models/llama3",
  gpu = "nvidia"
)
print(spec)
#> <airgap_container_spec>
#>   Backend:       ollama
#>   Image:         ollama/ollama@sha256:aaaaaaaaaaaa...
#>   Network mode:  none
#>   Read-only:     TRUE | Cap-drop: ALL
#>   Model mount:   /srv/models/llama3 -> /models:ro
#>   GPU:           nvidia (all)
#>   Spec digest:   sha256:e3e4ddc2329c698ea1363e9a943cb7fae03bd1a3592dc233d9c2dabae893fb05
```
