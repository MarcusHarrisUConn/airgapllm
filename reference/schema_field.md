# Define a Strictly Typed Field in an Extraction Schema

Creates a field specification for use inside
[`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md).
Enforces strict scalar typing (`character`, `integer`, `numeric`,
`logical`, `enum`), explicit nullability, numeric bounds, string length
bounds, and PCRE regex patterns.

## Usage

``` r
schema_field(
  type = c("character", "integer", "numeric", "logical", "enum"),
  description = "",
  nullable = FALSE,
  values = NULL,
  min = NULL,
  max = NULL,
  pattern = NULL,
  min_length = NULL,
  max_length = NULL
)
```

## Arguments

- type:

  Character scalar field type: `"character"`, `"integer"`, `"numeric"`,
  `"logical"`, or `"enum"`.

- description:

  Character scalar human-readable instructions for the LLM.

- nullable:

  Logical scalar; whether JSON `null` (`NA` in R) is permitted. Defaults
  to `FALSE`.

- values:

  Character vector of allowed levels (required when `type = "enum"`).

- min:

  Optional numeric minimum bound (valid for `"integer"` and
  `"numeric"`).

- max:

  Optional numeric maximum bound (valid for `"integer"` and
  `"numeric"`).

- pattern:

  Optional PCRE regular expression constraint (valid for `"character"`).

- min_length:

  Optional non-negative integer minimum string length (valid for
  `"character"`).

- max_length:

  Optional positive integer maximum string length (valid for
  `"character"`).

## Value

An S3 object of class `"airgap_schema_field"`.

## Examples

``` r
schema_field("enum", values = c("low", "moderate", "high"), description = "Risk tier")
#> $type
#> [1] "enum"
#> 
#> $description
#> [1] "Risk tier"
#> 
#> $nullable
#> [1] FALSE
#> 
#> $values
#> [1] "low"      "moderate" "high"    
#> 
#> $min
#> NULL
#> 
#> $max
#> NULL
#> 
#> $pattern
#> NULL
#> 
#> $min_length
#> NULL
#> 
#> $max_length
#> NULL
#> 
#> attr(,"class")
#> [1] "airgap_schema_field"
schema_field("integer", min = 0L, max = 10L, description = "Severity rating")
#> $type
#> [1] "integer"
#> 
#> $description
#> [1] "Severity rating"
#> 
#> $nullable
#> [1] FALSE
#> 
#> $values
#> NULL
#> 
#> $min
#> [1] 0
#> 
#> $max
#> [1] 10
#> 
#> $pattern
#> NULL
#> 
#> $min_length
#> NULL
#> 
#> $max_length
#> NULL
#> 
#> attr(,"class")
#> [1] "airgap_schema_field"
```
