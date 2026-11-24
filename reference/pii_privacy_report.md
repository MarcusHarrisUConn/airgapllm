# Generate a Pre-Run Privacy Coverage Report Without Leaking Raw PII

Scans a character vector, data frame text column, or pseudonymized
result and returns aggregate PII detection counts and document coverage
rates by entity type. Raw input text and matched sensitive values are
strictly excluded from the returned object.

## Usage

``` r
pii_privacy_report(x, config = pii_config(), text_col = NULL)
```

## Arguments

- x:

  A character vector, a data frame (requiring `text_col`), or an
  `airgap_pseudonymized` object.

- config:

  An
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  configuration object.

- text_col:

  Character scalar column name when `x` is a data frame.

## Value

An S3 object of class `"airgap_privacy_report"` containing only
aggregate counts (`n_documents`, `n_documents_with_pii`,
`pct_documents_with_pii`, `total_entities`, `by_entity`,
`config_digest`, `generated_at`).

## Examples

``` r
notes <- c("Contact Dr. Alice Smith at alice@hospital.org.", "No identifiers here.")
pii_privacy_report(notes)
#> <airgap_privacy_report> (aggregate counts only; zero raw PII)
#>   Documents scanned:  2
#>   Documents with PII: 1 (50%)
#>   Total detections:   2
#>   By entity type:
#>     - email: 1 (1 docs, 50%)
#>     - person_name: 1 (1 docs, 50%)
```
