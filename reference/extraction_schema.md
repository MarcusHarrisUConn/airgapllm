# Define a Strict Structured Extraction Schema

Declares the typed output schema for
[`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md).
Each named argument must be a
[`schema_field()`](https://marcusharrisphd.com/airgapllm/reference/schema_field.md)
object. Computes a deterministic canonical `schema_digest` used for
checkpoint compatibility and audit trails.

## Usage

``` r
extraction_schema(
  ...,
  name = "extraction",
  description = "",
  strict_keys = TRUE
)
```

## Arguments

- ...:

  Named
  [`schema_field()`](https://marcusharrisphd.com/airgapllm/reference/schema_field.md)
  objects (or a single named list of `airgap_schema_field` objects).

- name:

  Character scalar schema identifier. Defaults to `"extraction"`.

- description:

  Optional character scalar description of the extraction task.

- strict_keys:

  Logical scalar; if `TRUE` (default), rejects JSON outputs containing
  unexpected extra keys not declared in the schema.

## Value

An S3 object of class `"airgap_schema"`.

## Examples

``` r
sc <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L),
  crisis_flag = schema_field("logical"),
  summary = schema_field("character", max_length = 200L)
)
print(sc)
#> <airgap_schema> 'extraction' (4 fields, strict_keys=TRUE)
#>   - sentiment: enum (values=[positive,neutral,negative])
#>   - severity: integer (min=0, max=10)
#>   - crisis_flag: logical
#>   - summary: character (max_len=200)
#>   Schema digest: sha256:b1ad10165d0a909b0f7eb4a07ae1e98e99363de622ab0d560efdd0f56882ad01
```
