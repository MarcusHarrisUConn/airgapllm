# IRB & HIPAA Compliance Walkthrough: Safe Harbor, Key Rotation, and Audit Packets

## Overview

Institutional Review Boards (IRBs) and HIPAA Security Officers typically
ask four concrete questions before approving a local large language
model (LLM) protocol on clinical, behavioral, or educational text:

1.  **What direct identifiers exist in the corpus before inference, and
    how are HIPAA Safe Harbor rules enforced?**
2.  **How are re-identification mapping tables protected at rest and
    rotated over multi-wave longitudinal studies?**
3.  **What guarantees prevent prompt-injected or memorized PII from
    leaking into model outputs, checkpoints, or compliance logs?**
4.  **What verifiable, PII-free documentation can be attached to the IRB
    submission and archived for institutional audit?**

This vignette walks step-by-step through the complete compliance
workflow using the bundled 100% fictional `synthetic_notes` dataset.

``` r

library(airgapllm)
data("synthetic_notes", package = "airgapllm")
synthetic_notes[, c("note_id", "domain", "site", "wave", "contains_synthetic_phi")]
#>    note_id           domain       site wave contains_synthetic_phi
#> 1  SYN_001 clinical_therapy Site_North    1                   TRUE
#> 2  SYN_002 clinical_therapy Site_South    1                   TRUE
#> 3  SYN_003 clinical_therapy  Site_West    1                   TRUE
#> 4  SYN_004 clinical_therapy Site_North    1                   TRUE
#> 5  SYN_005 clinical_therapy Site_South    1                   TRUE
#> 6  SYN_006 clinical_therapy  Site_West    1                  FALSE
#> 7  SYN_007      ema_journal Site_North    1                   TRUE
#> 8  SYN_008      ema_journal Site_South    1                   TRUE
#> 9  SYN_009      ema_journal  Site_West    2                  FALSE
#> 10 SYN_010      ema_journal Site_North    2                   TRUE
#> 11 SYN_011      ema_journal Site_South    2                  FALSE
#> 12 SYN_012  student_writing  Site_West    2                   TRUE
#> 13 SYN_013  student_writing Site_North    2                   TRUE
#> 14 SYN_014  student_writing Site_South    2                  FALSE
#> 15 SYN_015  student_writing  Site_West    2                   TRUE
#> 16 SYN_016 clinical_therapy Site_North    2                   TRUE
```

## Step 1: Pre-Inference Privacy Dry-Run (`pii_audit_dataframe()`)

Before starting any extraction job, run
[`pii_audit_dataframe()`](https://marcusharrisphd.com/airgapllm/reference/pii_audit_dataframe.md)
to inspect entity density, trigger HIPAA Safe Harbor alerts, detect
Unicode obfuscators, and inspect strictly redacted preview snippets—with
**zero raw PII** printed or stored in the audit object:

``` r

dry_run <- pii_audit_dataframe(
  data = synthetic_notes,
  text_col = "note_text",
  id_col = "note_id",
  high_density_threshold = 3L,
  preview_n = 4L
)
dry_run
#> <airgap_pii_audit> (pre-inference privacy dry-run; zero raw PII)
#>   Rows scanned:        16
#>   Rows with PII:       12 (75%)
#>   Total PII spans:     36
#>   High-density rows:   7 (>= 3 entities)
#>   Unicode-normalized:  0 row(s)
#>   Entity breakdown:
#>     - age_over_89: 3 (2 rows, 12.5%)
#>     - date: 6 (6 rows, 37.5%)
#>     - email: 3 (3 rows, 18.75%)
#>     - ip_address: 1 (1 rows, 6.25%)
#>     - mrn_id: 4 (4 rows, 25%)
#>     - person_name: 8 (6 rows, 37.5%)
#>     - phone: 4 (4 rows, 25%)
#>     - ssn: 1 (1 rows, 6.25%)
#>     - street_address: 2 (2 rows, 12.5%)
#>     - zip_code: 4 (4 rows, 25%)
#>   Advisories:
#>     [!] 7 row(s) exceed high-PII-density threshold (>= 3 entities/row); review custom_dictionary coverage before inference.
#>     [!] HIPAA Safe Harbor alert: 3 age > 89 reference(s) detected and scheduled for redaction.
#>     [!] HIPAA Safe Harbor alert: 4 geographic ZIP code / restricted 3-digit prefix span(s) detected.
#>     [!] High-sensitivity identifier alert: 1 SSN pattern(s) detected.
```

Inspect the strictly redacted previews to verify that domain-specific
terms (such as local clinic names or study codes) are not slipping
through:

``` r

dry_run$masked_previews
#> # A tibble: 4 × 3
#>   row_id  n_entities redacted_preview                                           
#>   <chr>        <int> <chr>                                                      
#> 1 SYN_016          7 Session Transcript Part 1: Patient: [REDACTED_PERSON_NAME]…
#> 2 SYN_001          4 Patient: [REDACTED_PERSON_NAME] ([REDACTED_MRN_ID]) met wi…
#> 3 SYN_003          4 [REDACTED_AGE_OVER_89] participant (age: [REDACTED_AGE_OVE…
#> 4 SYN_002          3 Follow-up with [REDACTED_PERSON_NAME] via [REDACTED_EMAIL]…
```

## Step 2: HIPAA Safe Harbor Rules (Ages \> 89 & Restricted 3-Digit ZIPs)

Under **45 CFR 164.514(b)(2)** (HIPAA Safe Harbor), ages over 89 must be
redacted/aggregated, full 5-digit US ZIP codes must be scrubbed, and the
17 three-digit ZIP prefixes with population 20,000 or fewer cannot be
retained. `airgapllm` enforces these rules automatically in
[`pii_default_entities()`](https://marcusharrisphd.com/airgapllm/reference/pii_default_entities.md):

``` r

# Inspect the 17 HHS restricted 3-digit ZIP prefixes
hipaa_restricted_zip3()
#>  [1] "036" "059" "063" "102" "203" "556" "692" "790" "821" "823" "830" "831"
#> [13] "878" "879" "884" "890" "893"

hipaa_examples <- c(
  "92-year-old participant (age: 92) residing in Hartford, CT 06103.",
  "89-year-old participant with SpO2 98% and dose 95 mg (non-age units preserved).",
  "Rural intake from ZIP prefix 036xx and ZIP 82101; non-restricted ZIP prefix 061."
)
pii_redact(hipaa_examples)
#> [1] "[REDACTED_AGE_OVER_89] participant (age: [REDACTED_AGE_OVER_89]) residing in Hartford, CT [REDACTED_ZIP_CODE]."
#> [2] "89-year-old participant with SpO2 98% and dose 95 mg (non-age units preserved)."                               
#> [3] "Rural intake from ZIP prefix [REDACTED_ZIP_CODE] and ZIP [REDACTED_ZIP_CODE]; non-restricted ZIP prefix 061."  
#> attr(,"pii_report")
#> <airgap_privacy_report> (aggregate counts only; zero raw PII)
#>   Documents scanned:  3
#>   Documents with PII: 2 (66.67%)
#>   Total detections:   5
#>   By entity type:
#>     - age_over_89: 2 (1 docs, 33.33%)
#>     - zip_code: 3 (2 docs, 66.67%)
```

## Step 3: Keyed Pseudonymization & Vault Master Key Rotation

For multi-wave longitudinal research where tracking entity coreference
across waves is valuable,
[`pii_pseudonymize()`](https://marcusharrisphd.com/airgapllm/reference/pii_pseudonymize.md)
maps identifiers deterministically via **RFC 5869 HKDF-SHA256 +
HMAC-SHA256** and isolates mappings in a separate `airgapllm_vault_v2`
file (`AES-256-CBC` + constant-time Encrypt-then-MAC `HMAC-SHA256`,
`0600` owner-only permissions).

Periodically—or when lab personnel rotate off a protocol—rotate the
vault’s at-rest encryption key atomically with
[`pii_vault_rotate_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_rotate_key.md)
while keeping historical pseudonym tokens seamlessly re-identifiable:

``` r

work_dir <- tempfile("airgap_irb_walkthrough_")
dir.create(work_dir)
vault_path <- file.path(work_dir, "study_vault.json")

key_wave1 <- pii_vault_key()
pse <- pii_pseudonymize(
  synthetic_notes$note_text[1:4],
  key = key_wave1,
  vault_path = vault_path,
  encrypt_vault = TRUE
)
pse$vault
#> <airgap_pii_vault> (sensitive mappings hidden)
#>   Vault ID:        vault_20261124T214336Z_f4e46a20
#>   Key fingerprint: 260fecc27b13fb83
#>   Stored tokens:   12
#>   By entity type:  age_over_89=2, date=2, email=1, mrn_id=1, person_name=2, phone=1, ssn=1, street_address=1, zip_code=1

# Rotate the vault master key atomically to a fresh 256-bit key
key_wave2 <- pii_vault_key()
rot <- pii_vault_rotate_key(vault_path, old_key = key_wave1, new_key = key_wave2)
rot[c("vault_id", "old_key_fingerprint", "new_key_fingerprint", "n_tokens")]
#> $vault_id
#> [1] "vault_20261124T214336Z_f4e46a20"
#> 
#> $old_key_fingerprint
#> [1] "260fecc27b13fb83"
#> 
#> $new_key_fingerprint
#> [1] "cb4d981efeeed23e"
#> 
#> $n_tokens
#> [1] 12

# The old key is immediately rejected; the new key restores text losslessly
identical(
  pii_reidentify(pse$text, vault = vault_path, key = key_wave2),
  synthetic_notes$note_text[1:4]
)
#> [1] TRUE
```

## Step 4: Schema-Enforced Extraction with Output PII Leakage Scanning

During
[`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md),
untrusted records are framed inside explicit
`<UNTRUSTED_RESEARCH_RECORD>` boundaries to resist embedded
prompt-injection attacks, and generated character outputs are scanned
post-inference (`output_pii_action = "redact"` by default) so any echoed
or memorized PII is scrubbed before hitting disk or returning to R:

``` r

audit_path <- file.path(work_dir, "study_audit.jsonl")
ck_path <- file.path(work_dir, "study_checkpoint.jsonl")

spec <- airgap_container_spec(
  backend = "ollama",
  image = "ollama/ollama",
  image_digest = paste0("sha256:", strrep("a", 64)),
  model_dir = "/srv/airgapllm/models",
  model_digest = paste0("sha256:", strrep("b", 64)),
  gpu = "nvidia"
)

coding_schema <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L),
  crisis_flag = schema_field("logical"),
  rationale = schema_field("character", max_length = 160L),
  name = "irb_clinical_coding_v1"
)

extracted <- airgap_extract(
  data = synthetic_notes[1:8, ],
  text_col = "note_text",
  schema = coding_schema,
  runtime = runtime_mock(model = "llama3.1:8b-instruct-q4_K_M", seed = 2026L),
  id_col = "note_id",
  pii_policy = "redact",
  output_pii_action = "redact",
  checkpoint_path = ck_path,
  audit_log_path = audit_path,
  container_spec = spec
)

extracted[, c("note_id", "sentiment", "severity", "crisis_flag", ".status", ".attempts")]
#> # A tibble: 8 × 6
#>   note_id sentiment severity crisis_flag .status .attempts
#>   <chr>   <chr>        <int> <lgl>       <chr>       <int>
#> 1 SYN_001 negative         7 TRUE        ok              1
#> 2 SYN_002 neutral          8 TRUE        ok              1
#> 3 SYN_003 negative         9 FALSE       ok              1
#> 4 SYN_004 positive         5 FALSE       ok              1
#> 5 SYN_005 neutral          2 FALSE       ok              1
#> 6 SYN_006 neutral          9 TRUE        ok              1
#> 7 SYN_007 neutral          9 FALSE       ok              1
#> 8 SYN_008 neutral          2 TRUE        ok              1
audit_log_verify(audit_path)
#> <airgap_audit_verification> [VALID]
#>   Entries verified: 1
#>   Chain head hash:  sha256:9d90196ba0e4099de019286db47873188c41c229bde24af2f5420541814915aa
```

## Step 5: Export a Self-Contained, SHA-256-Sealed IRB Compliance Packet

Finally, bundle every compliance artifact—the verified hash-chained
audit log, pre-flight isolation attestation, hardened
Docker/Compose/Apptainer container configs, Markdown and Quarto IRB
narratives, and a SHA-256 `packet_manifest.json` —into one
self-contained, zero-PII review directory via
[`export_irb_compliance_packet()`](https://marcusharrisphd.com/airgapllm/reference/export_irb_compliance_packet.md):

``` r

pkt_dir <- file.path(work_dir, "irb_submission_packet")
pkt <- export_irb_compliance_packet(
  out_dir = pkt_dir,
  extraction = extracted,
  audit_log_path = audit_path,
  container_spec = spec,
  study_title = "Offline Phenotyping of Synthetic Clinical & EMA Records",
  protocol_id = "IRB-2026-0412",
  institution = "University Research Center",
  regulatory_framework = c("HIPAA", "IRB")
)

pkt
#> <airgap_compliance_packet> [AUDIT: VERIFIED]
#>   Directory:     /tmp/RtmpHIJBi9/airgap_irb_walkthrough_1d8ba3def15/irb_submission_packet
#>   Artifacts:     7 file(s) + packet_manifest.json
#>   Audit head:    sha256:9d90196ba0e4099de019286db47873188c41c229bde24af2f5420541814915aa
#>   Packet digest: sha256:61198eb713ea721af02de603dd417e49227d32c016514d12c995e6068a47685d
pkt$files
#> # A tibble: 7 × 3
#>   file                       size_bytes sha256                                  
#>   <chr>                           <dbl> <chr>                                   
#> 1 audit_log.jsonl                  1517 sha256:c3d9fe02952ca2c1420bd0d224c42be5…
#> 2 container_apptainer.def          1040 sha256:d574f5d2268124e079fbd2c954508781…
#> 3 container_docker_run.sh           637 sha256:a8551f9fd3be621b107bfb1c4f91a32e…
#> 4 docker-compose.yml                945 sha256:327ac8de475168269f085dad0475d04d…
#> 5 irb_protocol_narrative.md        5121 sha256:5cd0bf258cb759477151118ea5565097…
#> 6 irb_protocol_narrative.qmd       5268 sha256:f1fbe05421ad214671c745b207b1c99e…
#> 7 preflight_attestation.json       2327 sha256:6527eb38e048e21ff91ffac6f9980edf…
```
