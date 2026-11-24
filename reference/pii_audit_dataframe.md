# Pre-Inference Privacy Dry-Run Audit for Research Data Frames

Performs a non-destructive pre-run PII inspection across a data frame
text column before calling
[`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md).
Produces aggregate per-entity counts, row coverage metrics,
high-PII-density row flags, HIPAA Safe Harbor advisories, Unicode
obfuscation warnings, and strictly redacted preview snippets containing
**zero raw sensitive values**.

## Usage

``` r
pii_audit_dataframe(
  data,
  text_col,
  config = pii_config(),
  id_col = NULL,
  high_density_threshold = 3L,
  preview_n = 5L,
  preview_chars = 120L
)
```

## Arguments

- data:

  A data frame containing text rows to audit.

- text_col:

  Character scalar name of the text column in `data`.

- config:

  An
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  configuration object.

- id_col:

  Optional character scalar column name for row identifiers.

- high_density_threshold:

  Positive integer minimum entity count in a single row to flag as
  high-PII-density (default `3L`).

- preview_n:

  Non-negative integer number of redacted preview snippets to include
  (default `5L`).

- preview_chars:

  Positive integer maximum preview snippet length (default `120L`).

## Value

An S3 object of class `"airgap_pii_audit"` containing `report`
(`airgap_privacy_report`), `row_summary` (tibble), `high_density_rows`
(character vector of row IDs), `obfuscated_rows` (integer count),
`warnings` (character vector), and `masked_previews` (tibble with zero
raw PII).

## Examples

``` r
data("synthetic_notes", package = "airgapllm")
aud <- pii_audit_dataframe(synthetic_notes, "note_text", id_col = "note_id")
aud
#> <airgap_pii_audit> (pre-inference privacy dry-run; zero raw PII)
#>   Rows scanned:        16
#>   Rows with PII:       12 (75%)
#>   Total PII spans:     36
#>   High-density rows:   7 (>= 3 entities)
#>   Unicode-normalized:  0 row(s)
#>   Entity breakdown:
#>     - age_over_89: 3 (2 rows, 12.5%)
#>     - date: 6 (6 rows, 37.5%)
#>     - email: 3 (3 rows, 18.75%)
#>     - ip_address: 1 (1 rows, 6.25%)
#>     - mrn_id: 4 (4 rows, 25%)
#>     - person_name: 8 (6 rows, 37.5%)
#>     - phone: 4 (4 rows, 25%)
#>     - ssn: 1 (1 rows, 6.25%)
#>     - street_address: 2 (2 rows, 12.5%)
#>     - zip_code: 4 (4 rows, 25%)
#>   Advisories:
#>     [!] 7 row(s) exceed high-PII-density threshold (>= 3 entities/row); review custom_dictionary coverage before inference.
#>     [!] HIPAA Safe Harbor alert: 3 age > 89 reference(s) detected and scheduled for redaction.
#>     [!] HIPAA Safe Harbor alert: 4 geographic ZIP code / restricted 3-digit prefix span(s) detected.
#>     [!] High-sensitivity identifier alert: 1 SSN pattern(s) detected.
```
