# Atomically Rotate the Master Encryption Key of a PII Vault

Authenticates and decrypts an existing `airgapllm_vault_v2` (or legacy
v1) vault file using `old_key`, updates the vault key fingerprint under
`new_key`, and atomically re-encrypts the vault at rest using fresh RFC
5869 HKDF-SHA256 subkeys, a brand-new 128-bit random salt, a fresh
128-bit random IV, AAD-bound HMAC-SHA256 authentication, and owner-only
(`0600`) file permissions. All existing token-to-value mappings are
preserved so previously pseudonymized outputs remain re-identifiable
with `new_key`.

## Usage

``` r
pii_vault_rotate_key(path, old_key, new_key, out_path = path, backup = FALSE)
```

## Arguments

- path:

  Character scalar path to the existing encrypted vault file.

- old_key:

  Current secret key used to authenticate and decrypt `path`.

- new_key:

  New secret key (e.g., from
  [`pii_vault_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_key.md))
  used to re-encrypt the vault. Must differ from `old_key`.

- out_path:

  Destination file path for the rotated vault. Defaults to `path`
  (in-place atomic replacement via temporary file + rename).

- backup:

  Logical scalar; if `TRUE` and `out_path == path`, preserves a `0600`
  backup copy at `paste0(path, ".bak")` prior to replacement. Defaults
  to `FALSE`.

## Value

A list with `path`, `vault_id`, `old_key_fingerprint`,
`new_key_fingerprint`, `n_tokens`, and `rotated_at`.

## Examples

``` r
k1 <- pii_vault_key()
k2 <- pii_vault_key()
vf <- tempfile(fileext = ".vault.json")
pse <- pii_pseudonymize("Patient Jane Doe (jane@example.org)", key = k1, vault_path = vf)
rot <- pii_vault_rotate_key(vf, old_key = k1, new_key = k2)
rot$new_key_fingerprint
#> [1] "0042e770268ab5dc"
pii_reidentify(pse$text, vault = vf, key = k2)
#> [1] "Patient Jane Doe (jane@example.org)"
unlink(vf)
```
