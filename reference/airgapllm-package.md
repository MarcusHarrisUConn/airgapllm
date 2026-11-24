# airgapllm: Verifiably Offline Containerized Local LLM Workflows

A privacy-first workbench for running reproducible, network-isolated
local open-weights large language models (`Ollama`, `llama.cpp`, `vLLM`)
on sensitive human-subjects research text governed by IRB, HIPAA, and
FERPA protocols.

## Core Architectural Pillars

- Air-Gapped Container Lifecycle, Hardware Sizing & Benchmarking:

  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md),
  [`emit_docker_run()`](https://marcusharrisphd.com/airgapllm/reference/emit_docker_run.md),
  [`emit_docker_compose()`](https://marcusharrisphd.com/airgapllm/reference/emit_docker_compose.md),
  [`emit_apptainer_def()`](https://marcusharrisphd.com/airgapllm/reference/emit_apptainer_def.md),
  [`verify_model_digest()`](https://marcusharrisphd.com/airgapllm/reference/verify_model_digest.md),
  [`is_loopback_endpoint()`](https://marcusharrisphd.com/airgapllm/reference/is_loopback_endpoint.md),
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md),
  [`estimate_vram_requirements()`](https://marcusharrisphd.com/airgapllm/reference/estimate_vram_requirements.md),
  [`recommend_runtime_config()`](https://marcusharrisphd.com/airgapllm/reference/recommend_runtime_config.md),
  and
  [`benchmark_local_runtime()`](https://marcusharrisphd.com/airgapllm/reference/benchmark_local_runtime.md).

- Pre-Inference Privacy, PII & k-Anonymity Engine:

  [`pii_default_entities()`](https://marcusharrisphd.com/airgapllm/reference/pii_default_entities.md),
  [`hipaa_restricted_zip3()`](https://marcusharrisphd.com/airgapllm/reference/hipaa_restricted_zip3.md),
  [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md),
  [`pii_detect()`](https://marcusharrisphd.com/airgapllm/reference/pii_detect.md),
  [`pii_redact()`](https://marcusharrisphd.com/airgapllm/reference/pii_redact.md),
  [`pii_privacy_report()`](https://marcusharrisphd.com/airgapllm/reference/pii_privacy_report.md),
  [`pii_audit_dataframe()`](https://marcusharrisphd.com/airgapllm/reference/pii_audit_dataframe.md),
  [`pii_vault_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_key.md),
  [`pii_pseudonymize()`](https://marcusharrisphd.com/airgapllm/reference/pii_pseudonymize.md),
  [`pii_reidentify()`](https://marcusharrisphd.com/airgapllm/reference/pii_reidentify.md),
  [`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md),
  [`pii_vault_load()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_load.md),
  [`pii_vault_rotate_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_rotate_key.md),
  [`assess_reidentification_risk()`](https://marcusharrisphd.com/airgapllm/reference/assess_reidentification_risk.md),
  and
  [`apply_k_anonymity()`](https://marcusharrisphd.com/airgapllm/reference/apply_k_anonymity.md).

- Resumable Schema-Enforced & Consensus Batch Extractor:

  [`chunk_clinical_texts()`](https://marcusharrisphd.com/airgapllm/reference/chunk_clinical_texts.md),
  [`schema_field()`](https://marcusharrisphd.com/airgapllm/reference/schema_field.md),
  [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md),
  [`as_json_schema()`](https://marcusharrisphd.com/airgapllm/reference/as_json_schema.md),
  [`validate_extraction()`](https://marcusharrisphd.com/airgapllm/reference/validate_extraction.md),
  [`build_repair_prompt()`](https://marcusharrisphd.com/airgapllm/reference/build_repair_prompt.md),
  [`runtime_ollama()`](https://marcusharrisphd.com/airgapllm/reference/runtime_ollama.md),
  [`runtime_openai_local()`](https://marcusharrisphd.com/airgapllm/reference/runtime_openai_local.md),
  [`runtime_mock()`](https://marcusharrisphd.com/airgapllm/reference/runtime_mock.md),
  [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md),
  [`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md),
  [`consensus_passes()`](https://marcusharrisphd.com/airgapllm/reference/consensus_accessors.md),
  [`consensus_diagnostics()`](https://marcusharrisphd.com/airgapllm/reference/consensus_accessors.md),
  and
  [`extraction_manifest()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md).

- Immutable Audit Trail & IRB Protocol Generator:

  [`audit_log_append()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_append.md),
  [`audit_log_read()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_read.md),
  [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md),
  [`generate_irb_narrative()`](https://marcusharrisphd.com/airgapllm/reference/generate_irb_narrative.md),
  and
  [`export_irb_compliance_packet()`](https://marcusharrisphd.com/airgapllm/reference/export_irb_compliance_packet.md).

## See also

Useful links:

- <https://marcusharrisphd.com/airgapllm/>

- <https://github.com/MarcusHarrisUConn/airgapllm>

- Report bugs at <https://github.com/MarcusHarrisUConn/airgapllm/issues>

## Author

**Maintainer**: Marcus Harris <marcus.harris.uconn@gmail.com>
\[copyright holder\]

Authors:

- Marcus Harris <marcus.harris.uconn@gmail.com> \[copyright holder\]
