# Detect PII Entities in Character Text

Runs deterministic pure-R PII detection over a character vector covering
emails, SSNs, US/international phone numbers, dates/DOBs, MRNs/student
IDs, IPv4/IPv6 addresses, street addresses, person names, and
user-supplied custom regex patterns and dictionaries.

## Usage

``` r
pii_detect(text, config = pii_config(), include_values = TRUE)
```

## Arguments

- text:

  Character vector of documents to scan.

- config:

  An
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  configuration object.

- include_values:

  Logical scalar; if `TRUE` (default), includes the matched `match` text
  column for local inspection; if `FALSE`, replaces the column with
  `"[MASKED]"` while retaining exact offsets and `value_hash`.

## Value

A `tibble` with columns `doc_id`, `entity_type`, `start`, `end`,
`length`, `match`, and `value_hash`.

## Examples

``` r
txt <- c(
  "Dr. Jane Doe (MRN: 884210) emailed jane.doe@clinic.org on 2026-04-12.",
  "Call (555) 234-5678 regarding 742 Evergreen Terrace."
)
pii_detect(txt)
#> # A tibble: 5 × 7
#>   doc_id entity_type    start   end length match                      value_hash
#>    <int> <chr>          <int> <int>  <int> <chr>                      <chr>     
#> 1      1 person_name        1    12     12 Dr. Jane Doe               1060abeaf…
#> 2      1 mrn_id            15    25     11 MRN: 884210                d4eb1f691…
#> 3      1 email             36    54     19 jane.doe@clinic.org        63771e77b…
#> 4      1 date              59    68     10 2026-04-12                 6cb5308b6…
#> 5      2 street_address    16    51     36 5678 regarding 742 Evergr… 1ee7e75e5…
```
