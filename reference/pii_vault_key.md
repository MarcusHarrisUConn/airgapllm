# Generate a Cryptographic Secret Key for PII Pseudonymization Vaults

Generates a cryptographically strong random key via
[`openssl::rand_bytes()`](https://rdrr.io/pkg/openssl/man/rand_bytes.html)
encoded as a lowercase hexadecimal string (64 hex characters for 32
bytes / 256 bits).

## Usage

``` r
pii_vault_key(n_bytes = 32L)
```

## Arguments

- n_bytes:

  Integer number of random bytes (minimum 16, default `32L`).

## Value

Character scalar hexadecimal secret key.

## Examples

``` r
key <- pii_vault_key()
nchar(key)
#> [1] 64
```
