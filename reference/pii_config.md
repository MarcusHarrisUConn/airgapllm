# Configure Pre-Inference PII Detection and Redaction Rules

Builds a validated PII detection configuration controlling which
built-in entity classes are active, plus lab-supplied custom regex
patterns, custom literal dictionaries (e.g., local clinic names,
participant lists), and allowlisted terms that must not be flagged.

## Usage

``` r
pii_config(
  entities = pii_default_entities(),
  custom_patterns = NULL,
  custom_dictionary = NULL,
  allowlist = NULL,
  detect_unlabeled_names = TRUE,
  case_sensitive_dictionary = FALSE
)
```

## Arguments

- entities:

  Character vector of built-in entity types to detect. See
  [`pii_default_entities()`](https://marcusharrisphd.com/airgapllm/reference/pii_default_entities.md).

- custom_patterns:

  Optional named character vector of PCRE regular expressions, where
  names specify the entity type label (e.g.,
  `c(study_code = "STUDY-[0-9]{5}")`).

- custom_dictionary:

  Optional named list of character vectors containing literal sensitive
  terms grouped by entity type (e.g.,
  `list(clinic_name = c("Hartford General"), person_name = c("Maya Lin"))`).

- allowlist:

  Optional character vector of literal terms or phrases that must never
  be flagged as PII (case-insensitive exact match).

- detect_unlabeled_names:

  Logical scalar; if `TRUE` (default), enables capitalization-based
  detection of multi-word person names (filtered against common
  clinical/academic stopwords) in addition to titled (`Dr. ...`) and
  role-labeled (`Patient: ...`) names.

- case_sensitive_dictionary:

  Logical scalar; whether `custom_dictionary` matching is
  case-sensitive. Defaults to `FALSE`.

## Value

An S3 object of class `"airgap_pii_config"` with canonical
`config_digest`.

## Examples

``` r
cfg <- pii_config(
  custom_patterns = c(study_id = "UCONN-[0-9]{4}"),
  custom_dictionary = list(clinic = c("Valley Behavioral Clinic")),
  allowlist = c("Beck Depression Inventory")
)
print(cfg)
#> <airgap_pii_config>
#>   Entities:          email, ssn, street_address, zip_code, mrn_id, ip_address, phone, date, age_over_89, person_name
#>   Custom patterns:   1
#>   Dictionary terms:  1
#>   Allowlist terms:   1
#>   Unlabeled names:   TRUE
#>   Config digest:     sha256:5fa4db5bb1149bc7d2bef719b8af8912e5175edab8d36c9cc3a8d7a3a58389c8
```
