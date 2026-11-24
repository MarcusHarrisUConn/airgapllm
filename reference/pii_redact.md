# Redact Detected PII Entities from Text

Deterministically replaces detected PII spans with non-reversible typed
placeholders (default `"[REDACTED_{TYPE}]"`). Preserves `NA_character_`
elements and attaches an aggregate-only `"pii_report"` attribute
containing zero raw sensitive values.

## Usage

``` r
pii_redact(
  text,
  config = pii_config(),
  replacement = "[REDACTED_{TYPE}]",
  return_details = FALSE
)
```

## Arguments

- text:

  Character vector of documents to redact.

- config:

  An
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  configuration object.

- replacement:

  Character scalar replacement template. `{TYPE}` is substituted with
  the uppercased entity type (e.g., `"[REDACTED_EMAIL]"`).

- return_details:

  Logical scalar; if `TRUE`, returns a list with `text` and `report`
  (`airgap_privacy_report`); if `FALSE` (default), returns the redacted
  character vector with `attr(out, "pii_report")`.

## Value

A redacted character vector (or list when `return_details = TRUE`).

## Examples

``` r
pii_redact("Patient: Jane Doe (SSN 123-45-6789) emailed jane@example.org.")
#> [1] "Patient: [REDACTED_PERSON_NAME] (SSN [REDACTED_SSN]) emailed [REDACTED_EMAIL]."
#> attr(,"pii_report")
#> <airgap_privacy_report> (aggregate counts only; zero raw PII)
#>   Documents scanned:  1
#>   Documents with PII: 1 (100%)
#>   Total detections:   3
#>   By entity type:
#>     - email: 1 (1 docs, 100%)
#>     - person_name: 1 (1 docs, 100%)
#>     - ssn: 1 (1 docs, 100%)
```
