# Assess Quasi-Identifier Re-Identification Risk (k-Anonymity & l-Diversity)

Audits an extracted or clinical data frame across user-specified
quasi-identifiers (for example `age_band`, `zip3`, `gender`, `site`) to
quantify \$k\$-anonymity compliance, prosecutor and journalist
re-identification risks, sample uniqueness, and optional distinct
\$l\$-diversity for a sensitive outcome column. Equivalence class
diagnostics use opaque integer class IDs and aggregate counts only—never
logging raw participant records.

## Usage

``` r
assess_reidentification_risk(
  data,
  quasi_ids,
  k_min = 5L,
  sensitive_col = NULL,
  l_min = 2L,
  sampling_fraction = 1,
  include_na = TRUE
)
```

## Arguments

- data:

  A data frame or tibble to audit.

- quasi_ids:

  Character vector of one or more quasi-identifier column names present
  in `data`.

- k_min:

  Integer minimum required equivalence class size (must be `>= 2L`,
  default `5L`).

- sensitive_col:

  Optional character scalar name of a sensitive outcome column in `data`
  for distinct \$l\$-diversity auditing.

- l_min:

  Integer minimum required number of distinct non-NA values of
  `sensitive_col` within every equivalence class (must be `>= 2L`,
  default `2L`). Ignored when `sensitive_col = NULL`.

- sampling_fraction:

  Numeric population sampling fraction in `(0, 1]` used to compute
  conservative journalist re-identification risk upper bounds
  (`min(1, sampling_fraction / k)`). Defaults to `1` (conservative
  full-population / census upper bound equal to prosecutor risk).

- include_na:

  Logical scalar; if `TRUE` (default), `NA` values in `quasi_ids` form
  their own equivalence category (`"<NA>"`). If `FALSE`, rows containing
  `NA` in any quasi-identifier are excluded from equivalence class
  grouping and reported in `n_rows_excluded_na`.

## Value

An S3 object of class `"airgap_reid_risk"` containing:

- `n_rows`, `n_rows_evaluated`, `n_rows_excluded_na`, `n_classes`

- `quasi_ids`, `k_min`, `min_k`, `median_k`

- `n_unique_rows`, `pct_unique_rows`

- `n_violating_classes`, `n_violating_rows`, `pct_violating_rows`

- `passes_k_anonymity` (logical)

- `prosecutor_risk_max`, `prosecutor_risk_mean`

- `journalist_risk_max`, `journalist_risk_mean`, `sampling_fraction`

- `sensitive_col`, `l_min`, `min_l`, `n_l_violating_classes`,
  `n_l_violating_rows`, `pct_l_violating_rows`, `passes_l_diversity`

- `equivalence_classes`: privacy-safe tibble indexed by opaque
  `class_id`

- `row_class_size`: integer vector of class sizes aligned to `data` rows

- `row_violates`: logical vector flagging rows failing \$k\$-anonymity
  (or \$l\$-diversity when `sensitive_col` is supplied)

## Examples

``` r
df <- tibble::tibble(
  site = c(rep("North", 6), rep("South", 2), rep("West", 5)),
  wave = c(rep(1L, 6), rep(2L, 2), rep(1L, 5)),
  diagnosis = c("A", "B", "A", "B", "C", "A", "A", "A", "B", "C", "B", "C", "A")
)
assess_reidentification_risk(df, quasi_ids = c("site", "wave"),
                             k_min = 5L, sensitive_col = "diagnosis", l_min = 2L)
#> <airgap_reid_risk> [k-anonymity (k>=5): FAIL]
#>   Quasi-identifiers:   site, wave
#>   Rows evaluated:      13 / 13 across 3 equivalence class(es)
#>   Min / Median k:      2 / 5
#>   Sample uniques (k=1):0 (0%)
#>   Rows with k < 5:     2 (15.38%)
#>   Prosecutor risk:     max=0.5000 | mean=0.2308
#>   Journalist risk:     max=0.5000 | mean=0.2308 (f=1)
#>   l-diversity ('diagnosis', l>=2): FAIL (min_l=1, violating rows=2 [15.38%])
```
