# Access Long-Format Passes and Per-Field Diagnostics from Consensus Extractions

Retrieves the long-format pass table (`unit_id`, `pass_id`, `prompt_id`,
`seed`, and all extracted fields—directly compatible with multi-facet
psychometric reliability modeling such as generalizability studies) or
the per-field agreement summary table from an
[`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md)
result.

## Usage

``` r
consensus_passes(x)

consensus_diagnostics(x)
```

## Arguments

- x:

  An `airgap_consensus` tibble returned by
  [`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md).

## Value

A `tibble` of individual pass outputs (`consensus_passes()`) or
per-field agreement diagnostics (`consensus_diagnostics()`).

## Examples

``` r
df <- tibble::tibble(id = c("R1", "R2"), txt = c("Calm mood.", "Mild worry."))
sc <- extraction_schema(mood = schema_field("enum", values = c("calm", "worried")))
res <- airgap_extract_consensus(df, "txt", sc, runtime_mock(), n_passes = 3L, id_col = "id")
consensus_diagnostics(res)
#> # A tibble: 1 × 6
#>   field type  n_valid_rows mean_agreement pct_unanimous n_ties
#>   <chr> <chr>        <int>          <dbl>         <dbl>  <int>
#> 1 mood  enum             2          0.833            50      0
consensus_passes(res)
#> # A tibble: 6 × 7
#>   unit_id pass_id prompt_id  seed mood    .status .attempts
#>   <chr>   <chr>   <chr>     <int> <chr>   <chr>       <int>
#> 1 R1      pass_01 P1           42 calm    ok              1
#> 2 R2      pass_01 P1           42 worried ok              1
#> 3 R1      pass_02 P1           43 worried ok              1
#> 4 R2      pass_02 P1           43 worried ok              1
#> 5 R1      pass_03 P1           44 worried ok              1
#> 6 R2      pass_03 P1           44 worried ok              1
```
