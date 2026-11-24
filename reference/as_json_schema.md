# Convert an `airgap_schema` to a Standard JSON Schema Object

Produces a JSON Schema list representation compatible with Ollama
structured output (`format`) and OpenAI-compatible local endpoints
(`response_format`).

## Usage

``` r
as_json_schema(schema)
```

## Arguments

- schema:

  An
  [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md)
  object.

## Value

A named list representing the JSON Schema.

## Examples

``` r
sc <- extraction_schema(score = schema_field("integer", min = 1L, max = 5L))
as_json_schema(sc)
#> $type
#> [1] "object"
#> 
#> $title
#> [1] "extraction"
#> 
#> $properties
#> $properties$score
#> $properties$score$type
#> [1] "integer"
#> 
#> $properties$score$minimum
#> [1] 1
#> 
#> $properties$score$maximum
#> [1] 5
#> 
#> 
#> 
#> $required
#> $required[[1]]
#> [1] "score"
#> 
#> 
#> $additionalProperties
#> [1] FALSE
#> 
```
