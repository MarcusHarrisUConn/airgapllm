# Save a PII Pseudonymization Vault to a Separate Local File

Persists an `airgap_pii_vault` to disk separately from model prompts and
audit logs. When `encrypt = TRUE` (the default), derives fresh
independent encryption and authentication keys via RFC 5869 HKDF-SHA256
using a per-save random salt and fresh 128-bit IV, encrypts with
AES-256-CBC, authenticates envelope metadata + salt + IV + ciphertext
via Encrypt-then-MAC HMAC-SHA256, and enforces owner-only (`0600`) file
permissions.

## Usage

``` r
pii_vault_save(vault, path, key = NULL, encrypt = TRUE)
```

## Arguments

- vault:

  An `airgap_pii_vault` object (e.g., from `pii_pseudonymize()$vault`).

- path:

  Character scalar destination file path.

- key:

  Secret key (required when `encrypt = TRUE`).

- encrypt:

  Logical scalar; encrypt vault at rest. Defaults to `TRUE`.

## Value

Invisibly returns `path`.

## Examples

``` r
key <- pii_vault_key()
p <- pii_pseudonymize("Email jane@example.org", key = key)
vf <- tempfile(fileext = ".vault.json")
pii_vault_save(p$vault, vf, key = key)
loaded <- pii_vault_load(vf, key = key)
unlink(vf)
```
