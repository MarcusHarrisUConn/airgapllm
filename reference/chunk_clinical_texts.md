# Deterministic Overlapping Chunker for Long Clinical Transcripts

Splits long unstructured documents (such as therapy transcripts,
qualitative interviews, or multi-page clinical histories) that exceed
local LLM context windows into deterministic, overlapping chunks aligned
on paragraph or sentence boundaries while preserving `doc_id`,
`chunk_index`, character offsets, and unique `chunk_id` provenance for
re-aggregation.

## Usage

``` r
chunk_clinical_texts(
  data,
  text_col,
  id_col = NULL,
  max_chars = 3000L,
  overlap_chars = 250L,
  split_on = c("paragraph", "sentence", "character")
)
```

## Arguments

- data:

  A data frame containing documents to chunk.

- text_col:

  Character scalar name of the text column in `data`.

- id_col:

  Optional character scalar column name supplying unique document IDs.
  If `NULL`, synthesizes `"1"`, `"2"`, ..., `"N"`.

- max_chars:

  Positive integer maximum character length per chunk (minimum `50L`,
  default `3000L`).

- overlap_chars:

  Non-negative integer character overlap carried from the end of each
  chunk into the start of the next chunk (must be strictly less than
  `max_chars`, default `250L`).

- split_on:

  Character scalar boundary preference: `"paragraph"` (default, prefers
  blank-line paragraph breaks before falling back to sentence/word
  breaks), `"sentence"`, or `"character"`.

## Value

A `tibble` with columns `doc_id`, `chunk_id`, `chunk_index`, `n_chunks`,
`start_char`, `end_char`, `char_count`, and `chunk_text`.

## Examples

``` r
long_df <- tibble::tibble(
  doc_id = "T01",
  transcript = paste(
    rep("Patient described steady progress with sleep hygiene and mindfulness exercises.", 12),
    collapse = " "
  )
)
chunks <- chunk_clinical_texts(long_df, "transcript", id_col = "doc_id",
                               max_chars = 300L, overlap_chars = 60L)
chunks[, c("doc_id", "chunk_id", "chunk_index", "n_chunks", "char_count")]
#> # A tibble: 4 × 5
#>   doc_id chunk_id      chunk_index n_chunks char_count
#>   <chr>  <chr>               <int>    <int>      <int>
#> 1 T01    T01_chunk_001           1        4        240
#> 2 T01    T01_chunk_002           2        4        296
#> 3 T01    T01_chunk_003           3        4        296
#> 4 T01    T01_chunk_004           4        4        295
```
