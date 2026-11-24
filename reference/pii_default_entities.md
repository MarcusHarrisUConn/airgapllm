# Default Built-In PII Entity Types

Returns the default ordered vector of built-in PII entity types
supported by
[`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md),
[`pii_detect()`](https://marcusharrisphd.com/airgapllm/reference/pii_detect.md),
[`pii_redact()`](https://marcusharrisphd.com/airgapllm/reference/pii_redact.md),
and
[`pii_pseudonymize()`](https://marcusharrisphd.com/airgapllm/reference/pii_pseudonymize.md).

## Usage

``` r
pii_default_entities()
```

## Value

A character vector of built-in entity type identifiers.

## Examples

``` r
pii_default_entities()
#>  [1] "email"          "ssn"            "street_address" "zip_code"      
#>  [5] "mrn_id"         "ip_address"     "phone"          "date"          
#>  [9] "age_over_89"    "person_name"   
```
