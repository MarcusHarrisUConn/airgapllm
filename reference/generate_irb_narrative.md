# Generate Ready-to-Paste IRB / HIPAA Methods & Data-Security Documentation

Renders standardized Markdown or Quarto Methods and Data-Security
protocol boilerplate populated directly from a verified
[`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
result, `airgap_run_manifest`, `airgap_audit_entry`, or hash-chained
JSONL audit log file. Never includes raw participant text or sensitive
PII values—only cryptographic provenance digests, isolation
attestations, and aggregate PII redaction counts.

## Usage

``` r
generate_irb_narrative(
  source,
  study_title = NULL,
  protocol_id = NULL,
  institution = NULL,
  pi_name = NULL,
  regulatory_framework = c("HIPAA", "IRB"),
  format = c("markdown", "quarto"),
  include_technical_appendix = TRUE,
  file = NULL
)
```

## Arguments

- source:

  An `airgap_extraction` object, an `airgap_run_manifest`, an
  `airgap_audit_entry`, or a character scalar file path to a JSONL audit
  log (verified via
  [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md)
  before rendering).

- study_title:

  Optional character scalar study title.

- protocol_id:

  Optional character scalar IRB protocol identifier (e.g.,
  `"IRB-2026-0412"`).

- institution:

  Optional character scalar institutional name.

- pi_name:

  Optional character scalar Principal Investigator name (for protocol
  header only; omitted when `NULL`).

- regulatory_framework:

  Character vector of applicable frameworks from
  `c("HIPAA", "IRB", "FERPA")`. Defaults to `c("HIPAA", "IRB")`.

- format:

  Character scalar output format: `"markdown"` (default) or `"quarto"`.

- include_technical_appendix:

  Logical scalar; include a Markdown cryptographic provenance &
  aggregate PII redaction table. Defaults to `TRUE`.

- file:

  Optional file path to write the rendered protocol snippet.

## Value

A character scalar of class `"airgap_irb_narrative"`.

## Examples

``` r
df <- tibble::tibble(id = c("P1", "P2"), txt = c("Dr. Jane Doe visited.", "Follow-up ok."))
sc <- extraction_schema(status = schema_field("enum", values = c("stable", "acute")))
res <- airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id")
cat(generate_irb_narrative(res, protocol_id = "IRB-2026-001"))
#> ## Data Security & Air-Gapped Local AI Processing Protocol
#> 
#> - **Protocol ID:** IRB-2026-001
#> - **Regulatory Scope:** HIPAA / IRB
#> - **Run ID:** `run_20261124T214322Z_c19ba245` (2026-11-24T21:43:22Z)
#> 
#> ### 1. Offline Local AI Execution & Network Isolation
#> 
#> All automated natural language processing was executed strictly offline using `airgapllm` (v0.5.1, R 4.6.2) with **zero transmission of research data to external cloud APIs or third-party servers**. Inference was configured for local execution (`backend = "mock"`, endpoint class: `offline_mock`) under hardened container controls (`network_mode = "none"`, read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, read-only model volume mounts, and offline telemetry suppression). Automated pre-flight isolation checks (`preflight_isolation_check()`) returned **`PASS`** (attestation hash: `sha256:89b471a31453c07cd1e10e5e5f34b63d3049a7214457b886ad203f537097472f`), confirming strict local/loopback confinement and proxy bypass prior to reading participant text.
#> 
#> ### 2. Pre-Inference De-Identification & Privacy Safeguards
#> 
#> Prior to prompt construction, all unstructured text was processed in-memory by the deterministic pure-R `airgapllm` PII detection and redaction engine (`pii_policy = "redact"`, config digest `sha256:f76846ac5dfd228489ebd8dcb73058007a0acb02b83c072fc0baeda2f2c59119`). A total of **1** direct identifier span(s) across **1** entity class(es) were replaced with non-reversible typed placeholders (e.g., `[REDACTED_PERSON_NAME]`, `[REDACTED_EMAIL]`) before any text reached the local inference runtime.
#> 
#> Input text is canonicalized against Unicode homoglyphs and zero-width obfuscators prior to scanning, including HIPAA Safe Harbor controls for ages > 89 and geographic ZIP codes (including the 17 restricted 3-digit prefixes). Untrusted research text is wrapped in explicit data-boundary delimiters to mitigate embedded prompt-injection attacks, and generated character outputs undergo post-inference PII leakage scanning (0 post-inference leak(s) detected/mitigated). Neither raw participant text nor raw PII strings are persisted in crash-recovery checkpoints or compliance logs. Audit log writes enforce a strict schema allowlist and automated PII scanning that aborts execution if any raw text key or sensitive identifier is encountered.
#> 
#> ### 3. Model Provenance, Schema Enforcement & Reproducibility
#> 
#> Structured extraction used local open-weights model `mock-llama-3.1-8b-instruct-q4` (weight SHA-256: `sha256:0000000000000000000000000000000000000000000000000000000000000000`) with deterministic decoding parameters (`temperature = 0`, `seed = 42`, `top_p = 1`). Every model generation was validated against a strictly typed output schema (schema SHA-256: `sha256:0ba7ce2706f45ba29944726a7596bb7acbee7d95e8c789cc64ba189eff5ba658`; prompt template SHA-256: `sha256:4e9b8c3227a180f5b90b28b2115eb2c9ea3e2de1e05c27254579050f58043d42`) with bounded structured repair retries for malformed outputs and atomic row-level JSONL checkpointing. Across **2** input record(s), **2** succeeded and **0** failed (0 resumed from checkpoint; 0 structured repair retries).
#> 
#> ### 4. Immutable Compliance Audit Trail
#> 
#> Run provenance is recorded in a tamper-evident, SHA-256 hash-chained JSONL audit log linking each entry to its predecessor from `GENESIS`. Audit verification status: **Not persisted to external JSONL audit log**.
#> 
#> ### Technical Provenance Summary
#> 
#> | Control / Artifact | Verified Value |
#> | :--- | :--- |
#> | Isolation Pre-Flight Status | `PASS` (`sha256:89b471a31453c07cd1e10e5e5f34b63d3049a7214457b886ad203f537097472f`) |
#> | Endpoint Class | `offline_mock` |
#> | Container Backend / Network | `mock` / `none` |
#> | Container Image Digest | `not pinned` |
#> | Container Spec Digest | `not supplied` |
#> | Model Name | `mock-llama-3.1-8b-instruct-q4` |
#> | Model Weight SHA-256 | `sha256:0000000000000000000000000000000000000000000000000000000000000000` |
#> | Prompt Template SHA-256 | `sha256:4e9b8c3227a180f5b90b28b2115eb2c9ea3e2de1e05c27254579050f58043d42` |
#> | Output Schema SHA-256 | `sha256:0ba7ce2706f45ba29944726a7596bb7acbee7d95e8c789cc64ba189eff5ba658` |
#> | Decoding Seed / Temperature | `42` / `0` |
#> | Pre-Inference PII Policy | `redact` (`1` detections) |
#> | Rows Processed (OK / Failed) | `2` (`2` / `0`) |
#> | Audit Chain Head Hash | `N/A` |
#> | Software Environment | `airgapllm 0.5.1` / `R 4.6.2` |
#> 
#> #### Aggregate Pre-Inference PII Redaction Counts (Zero Raw Values Stored)
#> 
#> | Entity Type | Count |
#> | :--- | ---: |
#> | `person_name` | 1 |
```
