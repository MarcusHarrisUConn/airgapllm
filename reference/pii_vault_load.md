# Load a Saved PII Pseudonymization Vault from Disk

Reads and (if encrypted) authenticates and decrypts an
`airgap_pii_vault` file written by
[`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md).
Verifies the HMAC-SHA256 authentication tag in constant time BEFORE
decryption to defeat padding-oracle and timing attacks while never
exposing plaintext or key material in error messages.

## Usage

``` r
pii_vault_load(path, key = NULL)
```

## Arguments

- path:

  Character scalar path to the vault file.

- key:

  Secret key (required when the vault file is encrypted).

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
#>   Vault ID:        vault_20261124T193326Z_711e249f
#>   Key fingerprint: 78f23e27105d3a9c
#>   Stored tokens:   1
#>   By entity type:  email=1
unlink(vf)
```
