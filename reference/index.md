# Package index

## Air-Gapped Container Lifecycle & GPU Sizing

Generate pinned, network-isolated Docker and HPC Apptainer
configurations, verify model SHA-256 digests, and right-size GPUs.

- [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md)
  : Define a Hardened Air-Gapped Local LLM Container Specification

- [`emit_docker_run()`](https://marcusharrisphd.com/airgapllm/reference/emit_docker_run.md)
  :

  Emit a Hardened `docker run` Command

- [`emit_docker_compose()`](https://marcusharrisphd.com/airgapllm/reference/emit_docker_compose.md)
  : Emit a Hardened Docker Compose YAML Configuration

- [`emit_apptainer_def()`](https://marcusharrisphd.com/airgapllm/reference/emit_apptainer_def.md)
  :

  Emit an HPC Apptainer Definition File (`.def`)

- [`verify_model_digest()`](https://marcusharrisphd.com/airgapllm/reference/verify_model_digest.md)
  : Verify SHA-256 Digests of Local Model Weights

- [`is_loopback_endpoint()`](https://marcusharrisphd.com/airgapllm/reference/is_loopback_endpoint.md)
  : Classify and Validate Whether an Endpoint Is Strictly Local /
  Loopback

- [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md)
  : Run Pre-Flight Air-Gap Isolation and Integrity Verification

- [`estimate_vram_requirements()`](https://marcusharrisphd.com/airgapllm/reference/estimate_vram_requirements.md)
  : Estimate GPU VRAM Requirements for Local Open-Weights LLM Deployment

## Pre-Inference Privacy, PII & HIPAA Safe Harbor

Deterministic pure-R PII detection, redaction, HIPAA Safe Harbor rules
(ages \> 89 & restricted ZIP3), and zero-PII pre-run audits.

- [`pii_default_entities()`](https://marcusharrisphd.com/airgapllm/reference/pii_default_entities.md)
  : Default Built-In PII Entity Types
- [`hipaa_restricted_zip3()`](https://marcusharrisphd.com/airgapllm/reference/hipaa_restricted_zip3.md)
  : HIPAA Safe Harbor Restricted 3-Digit US ZIP Prefixes (45 CFR
  164.514(b)(2))
- [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md)
  : Configure Pre-Inference PII Detection and Redaction Rules
- [`pii_detect()`](https://marcusharrisphd.com/airgapllm/reference/pii_detect.md)
  : Detect PII Entities in Character Text
- [`pii_redact()`](https://marcusharrisphd.com/airgapllm/reference/pii_redact.md)
  : Redact Detected PII Entities from Text
- [`pii_privacy_report()`](https://marcusharrisphd.com/airgapllm/reference/pii_privacy_report.md)
  : Generate a Pre-Run Privacy Coverage Report Without Leaking Raw PII
- [`pii_audit_dataframe()`](https://marcusharrisphd.com/airgapllm/reference/pii_audit_dataframe.md)
  : Pre-Inference Privacy Dry-Run Audit for Research Data Frames

## Keyed Pseudonymization & Encrypted Vaults

Reversible RFC 5869 HKDF-SHA256 + HMAC-SHA256 pseudonymization with
AES-256-CBC Encrypt-then-MAC vaults and atomic key rotation.

- [`pii_vault_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_key.md)
  : Generate a Cryptographic Secret Key for PII Pseudonymization Vaults
- [`pii_pseudonymize()`](https://marcusharrisphd.com/airgapllm/reference/pii_pseudonymize.md)
  : Keyed Deterministic Reversible PII Pseudonymization (HMAC-SHA256)
- [`pii_reidentify()`](https://marcusharrisphd.com/airgapllm/reference/pii_reidentify.md)
  : Re-Identify Pseudonymized Text Using a Local Mapping Vault
- [`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md)
  : Save a PII Pseudonymization Vault to a Separate Local File
- [`pii_vault_load()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_load.md)
  : Load a Saved PII Pseudonymization Vault from Disk
- [`pii_vault_rotate_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_rotate_key.md)
  : Atomically Rotate the Master Encryption Key of a PII Vault

## Resumable Schema-Enforced Batch Extraction

Long-transcript chunking, strict typed schemas, automated structured
repair retries, and atomic JSONL crash-resumable batch extraction.

- [`chunk_clinical_texts()`](https://marcusharrisphd.com/airgapllm/reference/chunk_clinical_texts.md)
  : Deterministic Overlapping Chunker for Long Clinical Transcripts

- [`schema_field()`](https://marcusharrisphd.com/airgapllm/reference/schema_field.md)
  : Define a Strictly Typed Field in an Extraction Schema

- [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md)
  : Define a Strict Structured Extraction Schema

- [`as_json_schema()`](https://marcusharrisphd.com/airgapllm/reference/as_json_schema.md)
  :

  Convert an `airgap_schema` to a Standard JSON Schema Object

- [`validate_extraction()`](https://marcusharrisphd.com/airgapllm/reference/validate_extraction.md)
  :

  Validate a Raw Model Output Against an `airgap_schema`

- [`build_repair_prompt()`](https://marcusharrisphd.com/airgapllm/reference/build_repair_prompt.md)
  : Build a Structured Repair Prompt for Malformed Model Outputs

- [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
  : Run Crash-Resumable, Schema-Enforced Batch Extraction Over a Data
  Frame

- [`extraction_manifest()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md)
  [`extraction_privacy_report()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md)
  [`extraction_preflight()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md)
  [`extraction_vault()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md)
  [`extraction_throughput()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md)
  :

  Access Run Provenance and Privacy Metadata from an `airgap_extraction`

## Local Air-Gapped Inference Runtimes

Loopback-only local HTTP backends (Ollama, llama.cpp, vLLM) and
deterministic offline mock runtime.

- [`runtime_ollama()`](https://marcusharrisphd.com/airgapllm/reference/runtime_ollama.md)
  : Configure a Local Air-Gapped Ollama Runtime

- [`runtime_openai_local()`](https://marcusharrisphd.com/airgapllm/reference/runtime_openai_local.md)
  :

  Configure a Local Air-Gapped OpenAI-Compatible Runtime (`llama.cpp` /
  `vLLM`)

- [`runtime_mock()`](https://marcusharrisphd.com/airgapllm/reference/runtime_mock.md)
  : Configure a Deterministic Offline Mock Runtime

## Immutable Audit Trail & IRB Compliance Documentation

Tamper-evident SHA-256 hash-chained JSONL logs, IRB/HIPAA/FERPA
narrative generation, and sealed compliance packets.

- [`audit_log_append()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_append.md)
  : Append a Tamper-Evident Entry to an Immutable JSONL Audit Log
- [`audit_log_read()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_read.md)
  : Read Entries from an Immutable JSONL Audit Log
- [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md)
  : Verify Cryptographic Integrity and Zero-PII Invariants of an Audit
  Log
- [`generate_irb_narrative()`](https://marcusharrisphd.com/airgapllm/reference/generate_irb_narrative.md)
  : Generate Ready-to-Paste IRB / HIPAA Methods & Data-Security
  Documentation
- [`export_irb_compliance_packet()`](https://marcusharrisphd.com/airgapllm/reference/export_irb_compliance_packet.md)
  : Export a Self-Contained, Strictly PII-Free IRB / HIPAA Compliance
  Packet

## Datasets & Package Overview

Bundled 100% synthetic clinical/EMA/educational dataset and package
documentation.

- [`synthetic_notes`](https://marcusharrisphd.com/airgapllm/reference/synthetic_notes.md)
  : Synthetic Clinical, EMA, and Educational Research Notes Dataset
- [`airgapllm`](https://marcusharrisphd.com/airgapllm/reference/airgapllm-package.md)
  [`airgapllm-package`](https://marcusharrisphd.com/airgapllm/reference/airgapllm-package.md)
  : airgapllm: Verifiably Offline Containerized Local LLM Workflows
