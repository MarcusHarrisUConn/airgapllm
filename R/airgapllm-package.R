#' airgapllm: Verifiably Offline Containerized Local LLM Workflows
#'
#' A privacy-first workbench for running reproducible, network-isolated local
#' open-weights large language models (`Ollama`, `llama.cpp`, `vLLM`) on
#' sensitive human-subjects research text governed by IRB, HIPAA, and FERPA
#' protocols.
#'
#' @section Core Architectural Pillars:
#' \describe{
#'   \item{Air-Gapped Container Lifecycle, Hardware Sizing & Benchmarking}{[airgap_container_spec()],
#'     [emit_docker_run()], [emit_docker_compose()], [emit_apptainer_def()],
#'     [verify_model_digest()], [is_loopback_endpoint()],
#'     [preflight_isolation_check()], [estimate_vram_requirements()],
#'     [recommend_runtime_config()], and [benchmark_local_runtime()].}
#'   \item{Pre-Inference Privacy, PII & k-Anonymity Engine}{[pii_default_entities()],
#'     [hipaa_restricted_zip3()], [pii_config()], [pii_detect()],
#'     [pii_redact()], [pii_privacy_report()], [pii_audit_dataframe()],
#'     [pii_vault_key()], [pii_pseudonymize()], [pii_reidentify()],
#'     [pii_vault_save()], [pii_vault_load()], [pii_vault_rotate_key()],
#'     [assess_reidentification_risk()], and [apply_k_anonymity()].}
#'   \item{Resumable Schema-Enforced & Consensus Batch Extractor}{[chunk_clinical_texts()],
#'     [schema_field()], [extraction_schema()], [as_json_schema()],
#'     [validate_extraction()], [build_repair_prompt()], [runtime_ollama()],
#'     [runtime_openai_local()], [runtime_mock()], [airgap_extract()],
#'     [airgap_extract_consensus()], [consensus_passes()],
#'     [consensus_diagnostics()], and [extraction_manifest()].}
#'   \item{Immutable Audit Trail & IRB Protocol Generator}{[audit_log_append()],
#'     [audit_log_read()], [audit_log_verify()], [generate_irb_narrative()],
#'     and [export_irb_compliance_packet()].}
#' }
#'
#' @keywords internal
"_PACKAGE"

## usethis namespace: start
#' @importFrom rlang %||%
## usethis namespace: end
NULL
