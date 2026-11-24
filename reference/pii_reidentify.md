# Re-Identify Pseudonymized Text Using a Local Mapping Vault

Restores original values for `<<TYPE_HASH>>` pseudonym tokens using an
in-memory `airgap_pii_vault` or a vault file saved on disk via
[`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md).

## Usage

``` r
pii_reidentify(text, vault, key = NULL, cols = NULL)
```

## Arguments

- text:

  Character vector (or data frame when `cols` is supplied) containing
  pseudonymized strings.

- vault:

  An `airgap_pii_vault` object, an `airgap_pseudonymized` object, or a
  file path to a saved vault file.

- key:

  Optional secret key required when `vault` is a path to an encrypted
  vault file.

- cols:

  Optional character vector of column names to re-identify when `text`
  is a data frame. Defaults to all character columns.

## Value

A character vector (or data frame) with matching pseudonym tokens
restored to their original values.

## Examples

``` r
key <- pii_vault_key()
orig <- "Patient: Jane Doe (jane@example.org)"
res <- pii_pseudonymize(orig, key = key)
identical(pii_reidentify(res$text, res$vault), orig)
#> [1] TRUE
```
