# airgapllm

<!-- badges: start -->
<!-- badges: end -->

> **Verifiably offline, containerized local LLM workflows with PII redaction, schema-enforced batch extraction, and IRB/HIPAA audit trails in R.**

`airgapllm` is a turnkey, privacy-first R workbench enabling clinical, behavioral, educational, and medical researchers to run open-weights Large Language Models (`Ollama`, `llama.cpp`, `vLLM`) on sensitive human-subjects text—therapy notes, student writing, EMA journals, patient narratives—under strict **IRB, HIPAA, and FERPA** controls with zero external API leakage.

## Core Pillars

1. **Air-Gapped Container Lifecycle & GPU Sizing**
   - `airgap_container_spec()`, `emit_docker_run()`, `emit_docker_compose()`, and `emit_apptainer_def()` generate digest-pinned, hardened Docker (`--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, read-only model mounts, offline telemetry suppression, optional NVIDIA/ROCm GPU passthrough) and HPC Apptainer `.def` recipes for `Ollama`, `llama.cpp`, and `vLLM`.
   - `verify_model_digest()` computes streaming SHA-256 digests on local GGUF or sharded safetensors model files without loading weights into RAM, enforcing strict symlink and directory confinement.
   - `preflight_isolation_check()` and `is_loopback_endpoint()` validate container hardening posture, verify model SHA-256 pins, reject SSRF/non-loopback/spoofed URLs, fail closed on unbypassed outbound proxy env vars, and emit a cryptographically hashed (and optionally HMAC-signed) attestation record.
   - `estimate_vram_requirements()` right-sizes workstation and HPC GPU memory across quantizations (`Q4_K_M`, `Q6_K`, `Q8_0`, `FP16`), context lengths, and batch sizes.

2. **Pre-Inference Privacy, PII & HIPAA Safe Harbor Engine**
   - `pii_config()`, `pii_detect()`, `pii_redact()`, `pii_privacy_report()`, and `pii_audit_dataframe()` deterministically scan and scrub emails, SSNs, US/international phone numbers, dates/DOBs, MRNs/student IDs, IPv4/IPv6 addresses, street addresses, **HIPAA Safe Harbor ages > 89 and US ZIP codes / 17 restricted 3-digit prefixes** (`hipaa_restricted_zip3()`), titled/role-cued/unlabeled person names (with Unicode homoglyph & zero-width obfuscator normalization and O(M log M + N) ReDoS-safe execution), plus custom regexes, custom literal dictionaries, and clinical allowlists.
   - `pii_pseudonymize()`, `pii_reidentify()`, `pii_vault_key()`, `pii_vault_save()`, `pii_vault_load()`, and `pii_vault_rotate_key()` implement deterministic keyed reversible pseudonymization using **RFC 5869 HKDF-SHA256 + HMAC-SHA256**, storing raw mappings inside a separate **AES-256-CBC + HMAC-SHA256** (Encrypt-then-MAC with per-save random salts, fresh IVs, AAD binding, constant-time MAC verification, and atomic key rotation) local vault with owner-only (`0600`) permissions.

3. **Resumable Schema-Enforced Batch Extractor**
   - `chunk_clinical_texts()` splits long therapy transcripts and interviews into deterministic paragraph- or sentence-aligned overlapping chunks preserving `doc_id`, `chunk_id`, and offset provenance.
   - `extraction_schema()` and `schema_field()` declare strict scalar types (`character`, `integer`, `numeric`, `logical`, `enum`), nullability, numeric ranges, string lengths, and regex constraints, exporting standard JSON Schema (`as_json_schema()`).
   - `airgap_extract()` processes R data frames (including Latin-1 / Windows-1252 clinical CSV exports and 0-row frames) into strictly typed tibbles with mandatory pre-inference PII controls, delimited `<UNTRUSTED_RESEARCH_RECORD>` prompt-injection framing, **post-inference output PII leakage scanning** (`output_pii_action`), automated structured repair retries (`build_repair_prompt()`), and crash-resumable atomic per-row JSONL checkpointing with schema/prompt compatibility guards.
   - Pluggable strictly-local runtimes: `runtime_ollama()`, `runtime_openai_local()` (`llama.cpp` / `vLLM`, enforcing canonical loopback hosts and `noproxy = "*"`), and `runtime_mock()` (deterministic offline runtime for testing and dry-runs).

4. **Immutable IRB/HIPAA Audit Trail & Compliance Packets**
   - `audit_log_append()`, `audit_log_read()`, and `audit_log_verify()` maintain a tamper-evident SHA-256 hash-chained JSONL ledger (`GENESIS -> entry_1 -> entry_2 -> ...`) enforcing strict schema allowlists and active PII rejection (`airgap_audit_privacy_error`) so raw participant text never enters compliance logs.
   - `generate_irb_narrative()` renders ready-to-paste Markdown or Quarto IRB/HIPAA/FERPA Methods and Data-Security protocol boilerplate directly from verified runs and audit logs.
   - `export_irb_compliance_packet()` assembles a self-contained, SHA-256-sealed, zero-PII IRB/HIPAA audit directory ready for protocol submission.

## Installation

```r
# Install the development version from GitHub:
# install.packages("remotes")
remotes::install_github("MarcusHarrisUConn/airgapllm")
```

## Quick Start

```r
library(airgapllm)

# 1. Load bundled 100% synthetic clinical/EMA/educational dataset & run privacy dry-run
data("synthetic_notes", package = "airgapllm")
pii_audit_dataframe(synthetic_notes, "note_text", id_col = "note_id")

# 2. Size GPU VRAM & define a hardened, pinned air-gapped container spec
estimate_vram_requirements(8, quantization = "Q4_K_M", context_length = 8192L)

spec <- airgap_container_spec(
  backend = "ollama",
  image = "ollama/ollama",
  image_digest = paste0("sha256:", strrep("a", 64)),
  model_dir = "/srv/models/llama3",
  model_digest = paste0("sha256:", strrep("b", 64)),
  gpu = "nvidia"
)

# 3. Define a strict output schema & execute offline extraction with audit trail
schema <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L),
  crisis_flag = schema_field("logical")
)

audit_file <- tempfile(fileext = ".audit.jsonl")
ck_file <- tempfile(fileext = ".checkpoint.jsonl")

# Use runtime_ollama() or runtime_openai_local() in production; runtime_mock() offline
results <- airgap_extract(
  data = synthetic_notes[1:6, ],
  text_col = "note_text",
  schema = schema,
  runtime = runtime_mock(seed = 42L),
  id_col = "note_id",
  pii_policy = "redact",
  checkpoint_path = ck_file,
  audit_log_path = audit_file,
  container_spec = spec
)

results

# 4. Verify cryptographic audit chain & export SHA-256-sealed IRB compliance packet
audit_log_verify(audit_file)
pkt_dir <- file.path(tempdir(), "irb_compliance_packet")
export_irb_compliance_packet(
  out_dir = pkt_dir,
  extraction = results,
  audit_log_path = audit_file,
  container_spec = spec,
  protocol_id = "IRB-2026-0412",
  overwrite = TRUE
)
```

## Documentation & Guides

- **Website & Reference:** <https://marcusharrisphd.com/airgapllm/>
- **Security Audit:** See [SECURITY.md](SECURITY.md) for the v0.2.0 adversarial red-team audit, SSRF/injection mitigations, and cryptographic vault specification.
- **Architecture:** See [ARCHITECTURE.md](ARCHITECTURE.md) for the formal threat & privacy model, container hardening specification, and cryptographic audit log schema.
- **Vignettes:**
  - `vignette("getting-started", package = "airgapllm")`
  - `vignette("privacy-and-compliance", package = "airgapllm")`
  - `vignette("irb-hipaa-compliance-walkthrough", package = "airgapllm")`
  - `vignette("hpc-gpu-deployment", package = "airgapllm")`

## License

MIT © Marcus Harris
