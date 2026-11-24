# Build a Structured Repair Prompt for Malformed Model Outputs

Constructs a deterministic follow-up prompt instructing the local model
to repair schema or JSON syntax errors reported by
[`validate_extraction()`](https://marcusharrisphd.com/airgapllm/reference/validate_extraction.md).

## Usage

``` r
build_repair_prompt(original_prompt, invalid_output, errors, schema)
```

## Arguments

- original_prompt:

  Character scalar original extraction prompt.

- invalid_output:

  Character scalar previous invalid model output.

- errors:

  Character vector of validation error messages.

- schema:

  An
  [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md)
  object.

## Value

Character scalar repair prompt string.

## Examples

``` r
sc <- extraction_schema(score = schema_field("integer", min = 0L, max = 10L))
bad <- '{"score": 99}'
val <- validate_extraction(bad, sc)
cat(build_repair_prompt("Extract score.", bad, val$errors, sc))
#> Extract score.
#> 
#> --- REPAIR INSTRUCTION ---
#> Your previous output failed strict schema validation:
#> - Field 'score' value (99) exceeds max (10).
#> 
#> Previous invalid output:
#> {"score": 99}
#> 
#> Return ONLY a single valid JSON object conforming strictly to this JSON Schema (no markdown prose or extra keys):
#> {
#>   "type": "object",
#>   "title": "extraction",
#>   "properties": {
#>     "score": {
#>       "type": "integer",
#>       "minimum": 0,
#>       "maximum": 10
#>     }
#>   },
#>   "required": [
#>     "score"
#>   ],
#>   "additionalProperties": false
#> }
```
