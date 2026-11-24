# Privacy Engineering, Reversible Pseudonymization, Crash Recovery, and Audit Verification

## Overview

This vignette dives deeper into four operational safeguards required for
large-scale sensitive research deployments (10,000–100,000+ text records
on lab workstations or university HPC clusters):

1.  **Custom Domain Dictionaries & Allowlists** for high-precision PII
    de-identification.
2.  **Keyed Reversible Pseudonymization (HMAC-SHA256)** with encrypted
    local vaults (`AES-256-CBC` + `HMAC-SHA256` Encrypt-then-MAC).
3.  **Mid-Batch Crash Recovery** using atomic per-row JSONL
    checkpointing.
4.  **Tamper-Evident Audit Chain Verification** and zero-PII
    enforcement.

``` r

library(airgapllm)
library(tibble)
```

## 1. Custom Lab Dictionaries, Regexes, and Clinical Allowlists

Research corpora often include study-specific codes (e.g.,
`COHORT-2026-041`), local clinic names that function as indirect
identifiers, and standardized clinical instruments (e.g.,
`Beck Depression Inventory`) that must *not* be mistaken for person
names. Configure these once via
[`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md):

``` r

cfg <- pii_config(
  custom_patterns = c(cohort_id = "COHORT-[0-9]{4}-[0-9]{3}"),
  custom_dictionary = list(
    clinic = c("Valley Behavioral Health", "Oakridge Counseling")
  ),
  allowlist = c("Beck Depression Inventory", "Dr. Pepper")
)
cfg
#> <airgap_pii_config>
#>   Entities:          email, ssn, street_address, zip_code, mrn_id, ip_address, phone, date, age_over_89, person_name
#>   Custom patterns:   1
#>   Dictionary terms:  2
#>   Allowlist terms:   2
#>   Unlabeled names:   TRUE
#>   Config digest:     sha256:7852839643838b500b07d22a56be0921bf809d419a4d977c1ce6332af54317a7

notes <- c(
  "At Valley Behavioral Health (COHORT-2026-041), Dr. Elena Vance administered the Beck Depression Inventory.",
  "Follow-up with Dr. Elena Vance at elena.vance@vbh.org; SSN 123-45-6789 confirmed.",
  "Participant drank Dr. Pepper before session; Major Depressive Disorder symptoms stable."
)

pii_redact(notes, config = cfg)
#> [1] "At [REDACTED_CLINIC] ([REDACTED_COHORT_ID]), [REDACTED_PERSON_NAME] administered the Beck Depression Inventory."
#> [2] "Follow-up with [REDACTED_PERSON_NAME] at [REDACTED_EMAIL]; SSN [REDACTED_SSN] confirmed."                       
#> [3] "Participant drank Dr. Pepper before session; Major Depressive Disorder symptoms stable."                        
#> attr(,"pii_report")
#> <airgap_privacy_report> (aggregate counts only; zero raw PII)
#>   Documents scanned:  3
#>   Documents with PII: 2 (66.67%)
#>   Total detections:   6
#>   By entity type:
#>     - clinic: 1 (1 docs, 33.33%)
#>     - cohort_id: 1 (1 docs, 33.33%)
#>     - email: 1 (1 docs, 33.33%)
#>     - person_name: 2 (2 docs, 66.67%)
#>     - ssn: 1 (1 docs, 33.33%)
```

## 2. Keyed Reversible Pseudonymization & Encrypted Local Vaults

When longitudinal coreference matters (for example, tracking whether the
same clinician or family member appears across multiple sessions), use
[`pii_pseudonymize()`](https://marcusharrisphd.com/airgapllm/reference/pii_pseudonymize.md)
with a 256-bit secret key from
[`pii_vault_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_key.md).
Identical identifiers map deterministically to identical `<<TYPE_HASH>>`
tokens while raw values remain isolated inside an encrypted local vault
file:

``` r

secret_key <- pii_vault_key()
vault_file <- tempfile(fileext = ".vault.json")

pse <- pii_pseudonymize(
  notes,
  key = secret_key,
  config = cfg,
  vault_path = vault_file,
  encrypt_vault = TRUE
)

# Pseudonymized text preserves coreference for Dr. Elena Vance across rows 1 & 2
pse$text
#> [1] "At <<CLINIC_d2de9d36f9>> (<<COHORT_ID_dcc6c056e9>>), <<PERSON_NAME_ea8c8587c9>> administered the Beck Depression Inventory."
#> [2] "Follow-up with <<PERSON_NAME_ea8c8587c9>> at <<EMAIL_ac8b8e9f3b>>; SSN <<SSN_b0fb655a09>> confirmed."                       
#> [3] "Participant drank Dr. Pepper before session; Major Depressive Disorder symptoms stable."

# Printing the vault NEVER exposes raw sensitive mappings
pse$vault
#> <airgap_pii_vault> (sensitive mappings hidden)
#>   Vault ID:        vault_20261124T210617Z_7f80e037
#>   Key fingerprint: 53620bc0fed7ef4e
#>   Stored tokens:   5
#>   By entity type:  clinic=1, cohort_id=1, email=1, person_name=1, ssn=1
```

When authorized analysts need to restore original labels locally after
inference,
[`pii_reidentify()`](https://marcusharrisphd.com/airgapllm/reference/pii_reidentify.md)
authenticates the vault MAC, decrypts in memory, and reverses every
token losslessly:

``` r

restored <- pii_reidentify(pse$text, vault = vault_file, key = secret_key)
identical(restored, notes)
#> [1] TRUE
```

## 3. Crash-Resumable Checkpointing for Long HPC / GPU Batches

HPC Slurm jobs hit walltime limits and workstations occasionally restart
mid-run.
[`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
writes each completed row atomically to a JSONL checkpoint ledger
(storing only `row_id`, validated schema fields, status, and
`input_sha256`—never raw input text).

Here we simulate a hard crash after processing 3 of 8 rows, and then
resume seamlessly:

``` r

batch <- tibble(
  doc_id = sprintf("EMA_%03d", 1:8),
  journal = paste(
    "Participant Dr. Hannah Abbott (hannah@study.edu) daily EMA reflection",
    1:8
  )
)

ema_schema <- extraction_schema(
  affect = schema_field("enum", values = c("positive", "neutral", "negative")),
  stress = schema_field("integer", min = 1L, max = 5L),
  social_support = schema_field("logical")
)

ck_file <- tempfile(fileext = ".checkpoint.jsonl")

# Run 1: crashes after 3 rows
tryCatch(
  airgap_extract(
    batch, "journal", ema_schema,
    runtime = runtime_mock(seed = 99L, crash_after = 3L),
    id_col = "doc_id",
    checkpoint_path = ck_file
  ),
  airgap_simulated_crash = function(e) {
    message("Caught simulated interruption: ", conditionMessage(e))
  }
)
#> Caught simulated interruption: Simulated mid-batch crash after processing 3 row(s).

# Run 2: resume = TRUE skips the 3 committed rows and processes only EMA_004..EMA_008
rt_resume <- runtime_mock(seed = 99L)
resumed <- airgap_extract(
  batch, "journal", ema_schema,
  runtime = rt_resume,
  id_col = "doc_id",
  checkpoint_path = ck_file,
  resume = TRUE
)

extraction_throughput(resumed)
#> $rows_total
#> [1] 8
#> 
#> $rows_resumed
#> [1] 3
#> 
#> $rows_processed
#> [1] 5
#> 
#> $rows_succeeded
#> [1] 8
#> 
#> $rows_failed
#> [1] 0
#> 
#> $total_retries
#> [1] 0
#> 
#> $output_pii_leaks
#> [1] 0
#> 
#> $elapsed_sec
#> [1] 0.005
#> 
#> $rows_per_sec
#> [1] 1000
resumed
#> # A tibble: 8 × 8
#>   doc_id  affect   stress social_support .status .attempts .error .elapsed_ms
#>   <chr>   <chr>     <int> <lgl>          <chr>       <int> <chr>        <dbl>
#> 1 EMA_001 neutral       2 FALSE          ok              1 NA               2
#> 2 EMA_002 negative      3 TRUE           ok              1 NA               1
#> 3 EMA_003 negative      2 TRUE           ok              1 NA               1
#> 4 EMA_004 negative      3 FALSE          ok              1 NA               1
#> 5 EMA_005 positive      3 TRUE           ok              1 NA               1
#> 6 EMA_006 positive      4 FALSE          ok              1 NA               1
#> 7 EMA_007 negative      3 TRUE           ok              1 NA               1
#> 8 EMA_008 positive      3 FALSE          ok              1 NA               1
```

## 4. Audit Chain Tamper Detection & Zero-PII Guarantees

Every entry appended via
[`audit_log_append()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_append.md)
chains `prev_hash -> entry_hash` using canonical SHA-256 JSON hashing.
Modifying even a single character in an earlier entry invalidates the
cryptographic chain and is caught immediately by
[`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md):

``` r

audit_file <- tempfile(fileext = ".audit.jsonl")

audit_log_append(audit_file, resumed, metadata = list(site = "Site-A", wave = "Wave-1"))
#> <airgap_audit_entry> #1 [extraction_run]
#>   Run ID:       run_20261124T210617Z_af203687
#>   Timestamp:    2026-11-24T21:06:17Z
#>   Isolation:    PASS
#>   PII policy:   redact
#>   Prev hash:    GENESIS
#>   Entry hash:   sha256:05bc006bbd45666476635168827b4e5557e3ab7a8a48eea4f91f75c4b90c8e39
audit_log_append(
  audit_file,
  preflight_isolation_check(endpoint = "http://127.0.0.1:11434"),
  metadata = list(site = "Site-A")
)
#> <airgap_audit_entry> #2 [preflight_check]
#>   Run ID:       preflight_20261124T210617Z_088bbeea
#>   Timestamp:    2026-11-24T21:06:17Z
#>   Isolation:    PASS
#>   PII policy:   NA
#>   Prev hash:    sha256:05bc006bbd4566647
#>   Entry hash:   sha256:bfa119f599cb97b149a59c87c02ff93c0d6e6644342fe357fa75846f21726236

# Clean ledger verifies as VALID
audit_log_verify(audit_file)
#> <airgap_audit_verification> [VALID]
#>   Entries verified: 2
#>   Chain head hash:  sha256:bfa119f599cb97b149a59c87c02ff93c0d6e6644342fe357fa75846f21726236

# Simulate post-hoc tampering on line 1
tampered_file <- tempfile(fileext = ".tampered.jsonl")
lines <- readLines(audit_file)
lines[1L] <- sub("Wave-1", "Wave-9", lines[1L], fixed = TRUE)
writeLines(lines, tampered_file)

audit_log_verify(tampered_file)
#> <airgap_audit_verification> [TAMPERED / INVALID]
#>   Entries verified: 2
#>   Chain head hash:  sha256:bfa119f599cb97b149a59c87c02ff93c0d6e6644342fe357fa75846f21726236
#>   First invalid:    line 1
#>   [!] Line 1: Hash mismatch (tampered entry): stored sha256:05bc006bbd45666476635168827b4e5557e3ab7a8a48eea4f91f75c4b90c8e39 != computed sha256:8635f62eab7c3725e9b6a670b06634e51c75ceda9921e35a752ae1013b2e022e.
```

Attempting to write raw text keys or PII into an audit log is rejected
before touching disk:

``` r

tryCatch(
  audit_log_append(
    audit_file,
    list(run_id = "demo", raw_text = "Patient John Doe reported insomnia.")
  ),
  airgap_audit_privacy_error = function(e) {
    message("Blocked privacy violation: ", conditionMessage(e))
  }
)
#> Blocked privacy violation: Audit log privacy violation: raw text or sensitive keys are strictly
#> prohibited in audit logs.
#> ✖ Forbidden key(s): raw_text
```
