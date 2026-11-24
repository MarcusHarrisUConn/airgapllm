# Synthetic Clinical, EMA, and Educational Research Notes Dataset

A 100 percent fictional teaching dataset containing realistic synthetic
therapy session notes, ecological momentary assessment (EMA) journal
entries, and educational student reflections engineered specifically for
offline demonstrations, unit tests, and tutorials in `airgapllm`. All
names, emails (`@example.org`), phone numbers (`555-01xx` NANP reserved
range), street addresses, medical record numbers, social security
numbers, ages over 89, and geographic ZIP codes are completely
fabricated and correspond to no real individuals.

## Usage

``` r
synthetic_notes
```

## Format

A `tibble` with 16 rows and 6 columns:

- note_id:

  Character unique note identifier (`"SYN_001"` to `"SYN_016"`).

- domain:

  Character research domain (`"clinical_therapy"`, `"ema_journal"`, or
  `"student_writing"`).

- site:

  Character fictional study site label (`"Site_North"`, `"Site_South"`,
  or `"Site_West"`).

- wave:

  Integer longitudinal assessment wave (`1L` or `2L`).

- contains_synthetic_phi:

  Logical indicator of whether the row intentionally embeds fictional
  PII/PHI patterns.

- note_text:

  Character unstructured text body (including one multi-paragraph
  transcript for demonstrating
  [`chunk_clinical_texts()`](https://marcusharrisphd.com/airgapllm/reference/chunk_clinical_texts.md)
  and HIPAA Safe Harbor edge cases such as ages \> 89 and restricted
  3-digit ZIP prefixes).

## Source

100 percent synthetically constructed for `airgapllm` documentation and
reproducible offline verification.

## Examples

``` r
data("synthetic_notes", package = "airgapllm")
nrow(synthetic_notes)
#> [1] 16
pii_privacy_report(synthetic_notes, text_col = "note_text")
#> <airgap_privacy_report> (aggregate counts only; zero raw PII)
#>   Documents scanned:  16
#>   Documents with PII: 12 (75%)
#>   Total detections:   36
#>   By entity type:
#>     - age_over_89: 3 (2 docs, 12.5%)
#>     - date: 6 (6 docs, 37.5%)
#>     - email: 3 (3 docs, 18.75%)
#>     - ip_address: 1 (1 docs, 6.25%)
#>     - mrn_id: 4 (4 docs, 25%)
#>     - person_name: 8 (6 docs, 37.5%)
#>     - phone: 4 (4 docs, 25%)
#>     - ssn: 1 (1 docs, 6.25%)
#>     - street_address: 2 (2 docs, 12.5%)
#>     - zip_code: 4 (4 docs, 25%)
```
