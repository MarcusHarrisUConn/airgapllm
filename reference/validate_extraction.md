# Validate a Raw Model Output Against an `airgap_schema`

Parses a raw JSON string (or named list) and strictly checks all field
types, nullability rules, enum levels, numeric bounds, string length
bounds, regex patterns, and key strictness without silent coercion.

## Usage

``` r
validate_extraction(raw_output, schema)
```

## Arguments

- raw_output:

  Character scalar JSON string (or a named R list).

- schema:

  An
  [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md)
  object.

## Value

A list with elements:

- `valid`: logical scalar (`TRUE` if all checks pass)

- `data`: named list of strictly typed scalar R values (when valid) or
  `NULL`

- `errors`: character vector of specific validation diagnostic messages

## Examples

``` r
sc <- extraction_schema(
  label = schema_field("enum", values = c("yes", "no")),
  score = schema_field("integer", min = 0L, max = 10L)
)
validate_extraction('{"label": "yes", "score": 7}', sc)
#> $valid
#> [1] TRUE
#> 
#> $data
#> $data$label
#> [1] "yes"
#> 
#> $data$score
#> [1] 7
#> 
#> 
#> $errors
#> character(0)
#> 
validate_extraction('{"label": "maybe", "score": 99}', sc)
#> $valid
#> [1] FALSE
#> 
#> $data
#> NULL
#> 
#> $errors
#> [1] "Field 'label' value is not in allowed enum values [yes, no]."
#> [2] "Field 'score' value (99) exceeds max (10)."                  
#> 
```
