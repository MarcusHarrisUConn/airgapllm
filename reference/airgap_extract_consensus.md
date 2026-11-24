# Multi-Pass Consensus & Self-Consistency Structured Batch Extraction

Executes deterministic multi-pass local LLM extraction across multiple
random seeds and/or prompt template variants, aggregating strictly typed
fields via majority vote (`character`, `enum`, `logical`) or robust
central tendency (`numeric`, `integer`). Returns a strictly typed
consensus `tibble` with per-row agreement scores, per-field consensus
diagnostics, and a long-format pass table
([`consensus_passes()`](https://marcusharrisphd.com/airgapllm/reference/consensus_accessors.md))
directly compatible with multi-facet psychometric reliability auditing
(for example generalizability studies).

## Usage

``` r
airgap_extract_consensus(
  data,
  text_col,
  schema,
  runtime,
  n_passes = 3L,
  seeds = NULL,
  prompt_templates = NULL,
  id_col = NULL,
  numeric_agg = c("median", "trimmed_mean", "mean"),
  trim = 0.1,
  tie_policy = c("first", "na"),
  pii_policy = c("redact", "pseudonymize", "verified_deidentified"),
  pii_config = NULL,
  pii_key = NULL,
  vault = NULL,
  vault_path = NULL,
  encrypt_vault = TRUE,
  reidentify_output = FALSE,
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
  object.

- runtime:

  A local air-gapped runtime created by
  [`runtime_ollama()`](https://marcusharrisphd.com/airgapllm/reference/runtime_ollama.md),
  [`runtime_openai_local()`](https://marcusharrisphd.com/airgapllm/reference/runtime_openai_local.md),
  or
  [`runtime_mock()`](https://marcusharrisphd.com/airgapllm/reference/runtime_mock.md).

- n_passes:

  Integer number of passes when `seeds` is `NULL` (default `3L`). Must
  result in at least 2 total passes across seeds and prompts.

- seeds:

  Optional integer vector of explicit decoding seeds. When both `seeds`
  and `prompt_templates` are supplied, executes the full crossed
  `seeds x prompt_templates` design.

- prompt_templates:

  Optional character vector (named or unnamed) of prompt templates
  containing `"{text}"`.

- id_col:

  Optional character scalar column name supplying unique row IDs.

- numeric_agg:

  Aggregation rule for `numeric` and `integer` fields: `"median"`
  (default), `"trimmed_mean"`, or `"mean"`.

- trim:

  Fraction of observations trimmed from each end when
  `numeric_agg = "trimmed_mean"` (must be in `[0, 0.5)`, default `0.1`).

- tie_policy:

  Tie-breaking policy for categorical/logical majority vote: `"first"`
  (default, selects first winning level in pass order) or `"na"`
  (returns typed `NA` on exact ties).

- pii_policy:

  Pre-inference privacy policy: `"redact"` (default), `"pseudonymize"`,
  or `"verified_deidentified"`.

- pii_config:

  Optional
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  object.

- pii_key:

  Secret key required when `pii_policy = "pseudonymize"`.

- vault:

  Optional existing `airgap_pii_vault`.

- vault_path:

  Optional destination path for saving the encrypted vault.

- encrypt_vault:

  Logical scalar; encrypt saved vault file. Defaults to `TRUE`.

- reidentify_output:

  Logical scalar; re-identify character consensus columns locally when
  `pii_policy = "pseudonymize"`. Defaults to `FALSE`.

- max_retries:

  Maximum structured repair retries per row per pass (default `2L`).

- container_spec:

  Optional
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md).

- model_path:

  Optional local model weight path for pre-flight SHA-256 verification.

- allow_internal_network:

  Logical scalar passed to
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md).
  Defaults to `FALSE`.

- strict_proxy:

  Logical scalar passed to
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md).
  Defaults to `TRUE`.

- output_pii_action:

  Post-inference output PII scan policy: `"redact"` (default),
  `"error"`, `"warn"`, or `"none"`.

- audit_log_path:

  Optional path to append a hash-chained consensus run audit entry.

- run_id:

  Optional run identifier.

- progress:

  Logical scalar; emit brief CLI progress messages. Defaults to `FALSE`.

## Value

A `tibble` of class
`c("airgap_consensus", "tbl_df", "tbl", "data.frame")` containing the
row ID column, strictly typed consensus schema columns, `.agreement`
(row-level mean field agreement in `[0, 1]`), `.passes_ok`,
`.passes_total`, and `.status`. Retrieve the long-format pass table,
per-field diagnostics, and provenance metadata via
[`consensus_passes()`](https://marcusharrisphd.com/airgapllm/reference/consensus_accessors.md),
[`consensus_diagnostics()`](https://marcusharrisphd.com/airgapllm/reference/consensus_accessors.md),
and `attr(res, "airgap_manifest")`.

## Examples

``` r
data("synthetic_notes", package = "airgapllm")
sc <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L),
  crisis = schema_field("logical")
)
res <- airgap_extract_consensus(
  synthetic_notes[1:4, ],
  text_col = "note_text",
  schema = sc,
  runtime = runtime_mock(seed = 10L),
  n_passes = 3L,
  id_col = "note_id"
)
res
#> # A tibble: 4 × 8
#>   note_id sentiment severity crisis .agreement .passes_ok .passes_total .status
#>   <chr>   <chr>        <int> <lgl>       <dbl>      <int>         <int> <chr>  
#> 1 SYN_001 positive         6 TRUE        0.689          3             3 ok     
#> 2 SYN_002 negative         7 FALSE       0.489          3             3 ok     
#> 3 SYN_003 positive         9 FALSE       0.6            3             3 ok     
#> 4 SYN_004 negative         6 FALSE       0.6            3             3 ok     
consensus_diagnostics(res)
#> # A tibble: 3 × 6
#>   field     type    n_valid_rows mean_agreement pct_unanimous n_ties
#>   <chr>     <chr>          <int>          <dbl>         <dbl>  <int>
#> 1 sentiment enum               4          0.583            25      2
#> 2 severity  integer            4          0.533             0      0
#> 3 crisis    logical            4          0.667             0      0
head(consensus_passes(res))
#> # A tibble: 6 × 9
#>   unit_id pass_id prompt_id  seed sentiment severity crisis .status .attempts
#>   <chr>   <chr>   <chr>     <int> <chr>        <int> <lgl>  <chr>       <int>
#> 1 SYN_001 pass_01 P1           10 positive         9 TRUE   ok              1
#> 2 SYN_002 pass_01 P1           10 negative         8 FALSE  ok              1
#> 3 SYN_003 pass_01 P1           10 positive         7 FALSE  ok              1
#> 4 SYN_004 pass_01 P1           10 positive         6 FALSE  ok              1
#> 5 SYN_001 pass_02 P1           11 positive         0 TRUE   ok              1
#> 6 SYN_002 pass_02 P1           11 neutral          0 FALSE  ok              1
```
