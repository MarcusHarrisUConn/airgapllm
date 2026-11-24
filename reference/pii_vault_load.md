# Load a Saved PII Pseudonymization Vault from Disk

Reads and (if encrypted) authenticates and decrypts an
`airgap_pii_vault` file written by
[`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md).
Verifies the HMAC-SHA256 authentication tag in constant time BEFORE
decryption to defeat padding-oracle and timing attacks while never
exposing plaintext or key material in error messages. Refuses
unencrypted vault files whenever `key` is supplied or
`require_encrypted = TRUE` to prevent encryption-downgrade attacks.

## Usage

``` r
pii_vault_load(path, key = NULL, require_encrypted = !is.null(key))
```

## Arguments

- path:

  Character scalar path to the vault file.

- key:

  Secret key (required when the vault file is encrypted).

- require_encrypted:

  Logical scalar; if `TRUE` (default whenever `key` is supplied), aborts
  if the vault file has `encrypted = FALSE`. Pass
  `require_encrypted = FALSE` with `key = NULL` only when explicitly
  loading an unencrypted development vault.

## Value

An `airgap_pii_vault` object.

## Examples

``` r
key <- pii_vault_key()
pse <- pii_pseudonymize("Contact jane@example.org", key = key)
vf <- tempfile(fileext = ".vault.json")
pii_vault_save(pse$vault, vf, key = key)
loaded <- pii_vault_load(vf, key = key)
loaded
#> <airgap_pii_vault> (sensitive mappings hidden)
#>   Vault ID:        vault_20261124T210606Z_a72679e3
#>   Key fingerprint: 011672a96cc1e255
#>   Stored tokens:   1
#>   By entity type:  email=1
unlink(vf)
```
