# Run Pre-Flight Air-Gap Isolation and Integrity Verification

Validates container hardening posture (`--network none`, `--read-only`,
`--cap-drop ALL`, `no-new-privileges`, pinned image SHA-256 digest,
loopback host binding), confirms that any runtime endpoint is strictly
loopback / local Unix socket / offline mock, optionally verifies local
model weight SHA-256 digests on disk, checks outbound proxy environment
variables, and returns a cryptographically hashed (and optionally
HMAC-signed) pre-flight verification record.

## Usage

``` r
preflight_isolation_check(
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
)
```

## Arguments

- spec:

  Optional
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md)
  object.

- endpoint:

  Optional character URL or `airgap_runtime` object.

- model_path:

  Optional local path to model weights to verify on disk.

- expected_model_digest:

  Optional expected SHA-256 digest for `model_path`. Defaults to
  `spec$model_digest` when available.

- allow_internal_network:

  Logical scalar; if `FALSE` (default), requires
  `spec$network_mode == "none"`. If `TRUE`, also permits
  `network_mode == "internal"` when `host_bind` is strictly loopback.

- check_proxies:

  Logical scalar; inspect outbound proxy environment variables
  (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `SOCKS_PROXY`,
  case-insensitive). Defaults to `TRUE`.

- strict_proxy:

  Logical scalar; if `TRUE` (default), active outbound proxy variables
  without explicit `127.0.0.1` and `localhost` entries in `NO_PROXY`
  cause pre-flight verification to fail closed. Set to `FALSE` to
  downgrade proxy exposure to an advisory warning.

- allow_symlinks:

  Logical scalar passed to
  [`verify_model_digest()`](https://marcusharrisphd.com/airgapllm/reference/verify_model_digest.md)
  when verifying `model_path`. Defaults to `FALSE`.

- signing_key:

  Optional secret key (character or raw) to attach an HMAC-SHA256
  attestation signature to the verification record.

- error_on_fail:

  Logical scalar; if `TRUE`, aborts with an `airgap_isolation_error`
  when any required check fails. Defaults to `FALSE`.

## Value

An S3 object of class `"airgap_preflight"` with `passed`, `status`,
`checks` (tibble), `spec_digest`, `model_digest`, `endpoint_class`,
`checked_at`, `record_hash`, and `signature`.

## Examples

``` r
spec <- airgap_container_spec(
  backend = "ollama",
  image_digest = paste0("sha256:", strrep("a", 64)),
  model_dir = "/srv/models"
)
pf <- preflight_isolation_check(spec = spec, endpoint = "http://127.0.0.1:11434")
pf$passed
#> [1] TRUE
```
