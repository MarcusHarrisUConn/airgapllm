# Enforce k-Anonymity (and Optional l-Diversity) on a Research Table

Applies safe row suppression (`"suppress_rows"`) or rare-class masking
(`"mask_rare"`) to eliminate equivalence classes violating `k_min` (and
optionally `l_min` distinct values of `sensitive_col`). Under
`"mask_rare"`, if the masked fallback class itself has fewer than
`k_min` rows, additional smallest equivalence classes are progressively
generalized into `mask_value` until the masked class meets `k_min`
(preventing residual sub-`k` leakage). Returns the privacy-safe data
frame together with a before/after risk reduction summary without ever
logging raw participant values.

## Usage

``` r
apply_k_anonymity(
  data,
  quasi_ids,
  k_min = 5L,
  strategy = c("suppress_rows", "mask_rare"),
  mask_value = "[SUPPRESSED]",
  sensitive_col = NULL,
  l_min = 2L,
  include_na = TRUE
)
```

## Arguments

- data:

  A data frame or tibble.

- quasi_ids:

  Character vector of quasi-identifier column names.

- k_min:

  Integer minimum required equivalence class size (`>= 2L`, default
  `5L`).

- strategy:

  Character scalar de-identification strategy: `"suppress_rows"`
  (default, removes violating rows) or `"mask_rare"` (replaces
  quasi-identifiers of violating rows with `mask_value`).

- mask_value:

  Character scalar replacement value used when `strategy = "mask_rare"`
  (default `"[SUPPRESSED]"`).

- sensitive_col:

  Optional character scalar sensitive outcome column for \$l\$-diversity
  enforcement.

- l_min:

  Integer minimum required distinct values of `sensitive_col` per class
  (`>= 2L`, default `2L`).

- include_na:

  Logical scalar passed to
  [`assess_reidentification_risk()`](https://marcusharrisphd.com/airgapllm/reference/assess_reidentification_risk.md).
  Defaults to `TRUE`.

## Value

An S3 object of class `"airgap_k_anonymized"` containing `data`
(privacy-safe tibble), `strategy`, `k_min`, `l_min`, `n_rows_before`,
`n_rows_after`, `n_rows_suppressed`, `n_rows_masked`, `risk_before`, and
`risk_after`.

## Examples

``` r
df <- tibble::tibble(
  site = c(rep("North", 6), rep("South", 2), rep("West", 5)),
  wave = c(rep(1L, 6), rep(2L, 2), rep(1L, 5)),
  score = seq_len(13)
)
res <- apply_k_anonymity(df, quasi_ids = c("site", "wave"), k_min = 5L)
res
#> <airgap_k_anonymized> [strategy=suppress_rows, k_min=5]
#>   Rows:            13 -> 11 (suppressed=2, masked=0)
#>   k-anonymity:     FAIL -> PASS (min_k: 2 -> 5)
#>   Prosecutor max:  0.5000 -> 0.2000
```
