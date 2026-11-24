# Run Crash-Resumable, Schema-Enforced Batch Extraction Over a Data Frame

Processes text rows in an R data frame through a local air-gapped LLM
runtime into a strictly typed `tibble` with:

1.  Pre-flight air-gap isolation verification
    ([`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md)),

2.  Mandatory pre-inference PII redaction or keyed HMAC-SHA256
    pseudonymization (or explicit `"verified_deidentified"`
    attestation),

3.  Strict JSON schema validation
    ([`validate_extraction()`](https://marcusharrisphd.com/airgapllm/reference/validate_extraction.md))
    with automatic structured repair retries
    ([`build_repair_prompt()`](https://marcusharrisphd.com/airgapllm/reference/build_repair_prompt.md)),

4.  Crash-resumable atomic per-row JSONL checkpointing (never storing
    raw input text), and

5.  Optional automatic hash-chained PII-free IRB/HIPAA audit logging
    ([`audit_log_append()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_append.md)).

## Usage

``` r
airgap_extract(
  data,
  text_col,
  schema,
  runtime,
  prompt_template = NULL,
  id_col = NULL,
  pii_policy = c("redact", "pseudonymize", "verified_deidentified"),
  pii_config = NULL,
  pii_key = NULL,
  vault = NULL,
  vault_path = NULL,
  encrypt_vault = TRUE,
  reidentify_output = FALSE,
  checkpoint_path = NULL,
  resume = TRUE,
  retry_failed = FALSE,
  max_retries = 2L,
  container_spec = NULL,
  model_path = NULL,
  allow_internal_network = FALSE,
  strict_proxy = TRUE,
  output_pii_action = c("redact", "error", "warn", "none"),
  audit_log_path = NULL,
  run_id = NULL,
  progress = FALSE
)
```

## Arguments

- data:

  A data frame containing input text rows.

- text_col:

  Character scalar name of the text column in `data`.

- schema:

  An
  [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md)
  object defining output column types and constraints.

- runtime:

  A local air-gapped runtime created by
  [`runtime_ollama()`](https://marcusharrisphd.com/airgapllm/reference/runtime_ollama.md),
  [`runtime_openai_local()`](https://marcusharrisphd.com/airgapllm/reference/runtime_openai_local.md),
  or
  [`runtime_mock()`](https://marcusharrisphd.com/airgapllm/reference/runtime_mock.md).

- prompt_template:

  Optional character scalar prompt template containing `"{text}"`.
  Defaults to a strict JSON schema extraction prompt.

- id_col:

  Optional character scalar column name in `data` supplying unique
  non-NA row identifiers. If `NULL`, synthesizes `.row_id` as `"1"`,
  `"2"`, ..., `"N"`.

- pii_policy:

  Character scalar pre-inference privacy policy: `"redact"` (default),
  `"pseudonymize"`, or `"verified_deidentified"`.

- pii_config:

  Optional
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  object used when `pii_policy` is `"redact"` or `"pseudonymize"`.
  Defaults to
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md).

- pii_key:

  Secret key (e.g., from
  [`pii_vault_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_key.md))
  required when `pii_policy = "pseudonymize"`.

- vault:

  Optional existing `airgap_pii_vault` to accumulate mappings when
  `pii_policy = "pseudonymize"`.

- vault_path:

  Optional path to persist the separate encrypted PII vault when
  `pii_policy = "pseudonymize"`.

- encrypt_vault:

  Logical scalar; encrypt saved vault file. Defaults to `TRUE`.

- reidentify_output:

  Logical scalar; if `TRUE` and `pii_policy = "pseudonymize"`, locally
  re-identifies character output columns using the vault after
  inference. Defaults to `FALSE`.

- checkpoint_path:

  Optional path to an atomic JSONL checkpoint file enabling
  crash-resumable execution across interruptions.

- resume:

  Logical scalar; if `TRUE` (default) and `checkpoint_path` exists,
  skips rows already committed in the checkpoint. If `FALSE`, starts a
  fresh checkpoint file (overwriting any existing file at
  `checkpoint_path`).

- retry_failed:

  Logical scalar; when resuming from a checkpoint, whether to re-attempt
  rows previously recorded with `.status == "failed"`. Defaults to
  `FALSE`.

- max_retries:

  Non-negative integer maximum structured repair retries after an
  initial invalid generation. Defaults to `2L`.

- container_spec:

  Optional
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md)
  verified in pre-flight and recorded in the run manifest/audit trail.
  Defaults to `runtime$container_spec`.

- model_path:

  Optional path to local model weights verified against
  `container_spec$model_digest` or `runtime$model_digest` during
  pre-flight.

- allow_internal_network:

  Logical scalar passed to
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md).
  Defaults to `FALSE`.

- strict_proxy:

  Logical scalar passed to
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md)
  controlling whether unbypassed outbound proxy env vars fail closed.
  Defaults to `TRUE`.

- output_pii_action:

  Character scalar controlling post-inference PII leakage scanning of
  generated character schema fields (defending against prompt-injected
  or memorized PII echo): `"redact"` (default, scrubs leaked PII before
  checkpointing/returning), `"error"` (aborts with
  `airgap_output_pii_error`), `"warn"`, or `"none"`. Automatically
  skipped when `pii_policy = "verified_deidentified"` unless explicitly
  requested.

- audit_log_path:

  Optional path to an immutable hash-chained JSONL audit log appended
  via
  [`audit_log_append()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_append.md).

- run_id:

  Optional character scalar run identifier. Defaults to an
  auto-generated UTC run ID.

- progress:

  Logical scalar; emit brief CLI progress summary. Defaults to `FALSE`.

## Value

A `tibble` of class
`c("airgap_extraction", "tbl_df", "tbl", "data.frame")` containing the
row ID column, strictly typed schema columns, and per-row metadata
(`.status`, `.attempts`, `.error`, `.elapsed_ms`). Attachable provenance
objects are accessed via
[`extraction_manifest()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md),
[`extraction_privacy_report()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md),
[`extraction_preflight()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md),
[`extraction_vault()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md),
and
[`extraction_throughput()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md).

## Examples

``` r
df <- tibble::tibble(
  note_id = c("N1", "N2"),
  note_text = c(
    "Dr. Jane Doe (MRN: 102938) reports mild anxiety, sleep improved.",
    "Email bob@example.org for scheduling; mood stable."
  )
)
sc <- extraction_schema(
  severity = schema_field("enum", values = c("mild", "moderate", "severe")),
  score = schema_field("integer", min = 0L, max = 10L)
)
res <- airgap_extract(df, "note_text", sc, runtime_mock(), id_col = "note_id")
res
#> # A tibble: 2 × 7
#>   note_id severity score .status .attempts .error .elapsed_ms
#>   <chr>   <chr>    <int> <chr>       <int> <chr>        <dbl>
#> 1 N1      severe      10 ok              1 NA               3
#> 2 N2      mild         2 ok              1 NA               1
```
