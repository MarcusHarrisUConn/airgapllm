# Keyed Deterministic Reversible PII Pseudonymization (HMAC-SHA256)

Replaces detected PII entities with deterministic HMAC-SHA256 keyed
pseudonym tokens (e.g., `<<PERSON_NAME_a3f81c920b>>`) so the same
sensitive value maps consistently across documents while keeping
original identifiers isolated in a separate local mapping vault
(`airgap_pii_vault`).

## Usage

``` r
pii_pseudonymize(
  text,
  key,
  config = pii_config(),
  vault = NULL,
  vault_path = NULL,
  encrypt_vault = TRUE,
  token_length = 10L
)
```

## Arguments

- text:

  Character vector of documents to pseudonymize.

- key:

  Secret key (character string or raw vector, e.g., from
  [`pii_vault_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_key.md)).

- config:

  An
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  configuration object.

- vault:

  Optional existing `airgap_pii_vault` created with the same `key` to
  accumulate mappings across batches.

- vault_path:

  Optional file path where the mapping vault is immediately saved via
  [`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md).

- encrypt_vault:

  Logical scalar; encrypt saved vault file when `vault_path` is
  provided. Defaults to `TRUE`.

- token_length:

  Integer number of hex characters (8 to 32) from the HMAC-SHA256 digest
  used in each pseudonym token. Defaults to `10L`.

## Value

An S3 object of class `"airgap_pseudonymized"` with elements:

- `text`: pseudonymized character vector

- `vault`: separate `airgap_pii_vault` mapping tokens back to raw values

- `report`: aggregate-only `airgap_privacy_report` (zero raw PII)

- `vault_path`: saved vault path or `NULL`

## Examples

``` r
key <- pii_vault_key()
docs <- c("Dr. Jane Doe called (555) 234-5678.", "Follow-up with Dr. Jane Doe.")
res <- pii_pseudonymize(docs, key = key)
res$text
#> [1] "<<PERSON_NAME_12adf59a96>> called <<PHONE_16aa6e6107>>."
#> [2] "Follow-up with <<PERSON_NAME_12adf59a96>>."             
pii_reidentify(res$text, res$vault)
#> [1] "Dr. Jane Doe called (555) 234-5678." "Follow-up with Dr. Jane Doe."       
```
