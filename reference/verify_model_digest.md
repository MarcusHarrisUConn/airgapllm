# Verify SHA-256 Digests of Local Model Weights

Computes streaming SHA-256 digests of a local model file (e.g., GGUF or
safetensors) or a directory of sharded weight files without loading the
weights into memory, and optionally compares against a pinned expected
digest.

## Usage

``` r
verify_model_digest(
  path,
  expected_digest = NULL,
  algorithm = "sha256",
  error_on_mismatch = FALSE,
  root_dir = NULL,
  allow_symlinks = FALSE
)
```

## Arguments

- path:

  Character scalar path to a local model file or directory of model
  files.

- expected_digest:

  Optional expected SHA-256 digest string (for a single file or
  directory manifest) or named character vector mapping relative file
  paths to SHA-256 digests (for a directory).

- algorithm:

  Hash algorithm; currently `"sha256"`.

- error_on_mismatch:

  Logical scalar; if `TRUE` and verification fails, aborts with an
  `airgap_digest_error`. Defaults to `FALSE`.

- root_dir:

  Optional directory path that `path` must remain strictly confined
  within (blocks symlink escapes and path traversal).

- allow_symlinks:

  Logical scalar; if `FALSE` (default), rejects any symbolic links
  encountered at `path` or inside a model directory.

## Value

An S3 object of class `"airgap_digest_verification"` containing `path`,
`is_directory`, `algorithm`, `actual_digest`, `expected_digest`,
`matched`, `size_bytes`, `files` (tibble), and `verified_at`.

## Examples

``` r
tmp_model <- tempfile(fileext = ".gguf")
writeBin(charToRaw("mock-gguf-weights-v1"), tmp_model)
res <- verify_model_digest(tmp_model)
verify_model_digest(tmp_model, expected_digest = res$actual_digest)
#> <airgap_digest_verification> [MATCHED]
#>   Path:       /tmp/RtmpYwr7Bt/file1944436fb2d6.gguf
#>   Size bytes: 20
#>   Actual:     sha256:2a1762b7ed43674195cebce6e770011d1738919f1c866411ab76ab2de9b07aa1
#>   Expected:   sha256:2a1762b7ed43674195cebce6e770011d1738919f1c866411ab76ab2de9b07aa1
unlink(tmp_model)
```
