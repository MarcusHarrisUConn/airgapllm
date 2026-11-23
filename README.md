# airgapllm

<!-- badges: start -->
<!-- badges: end -->

> **Verifiably offline, containerized local LLM workflows with PII redaction, schema-enforced batch extraction, and IRB/HIPAA audit trails in R.**

`airgapllm` is a turnkey, privacy-first R workbench enabling clinical, behavioral, educational, and medical researchers to run open-weights Large Language Models (`Ollama`, `llama.cpp`, `vLLM`) on sensitive human-subjects text—therapy notes, student writing, EMA journals, patient narratives—under strict **IRB, HIPAA, and FERPA** controls with zero external API leakage.

## Core Pillars

1. **Air-Gapped Container Lifecycle Manager**
   - `airgap_container_spec()`, `emit_docker_run()`, `emit_docker_compose()`, and `emit_apptainer_def()` generate digest-pinned, hardened Docker (`--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, read-only model mounts, offline telemetry suppression, optional NVIDIA/ROCm GPU passthrough) and HPC Apptainer `.def` recipes for `Ollama`, `llama.cpp`, and `vLLM`.
   - `verify_model_digest()` computes streaming SHA-256 digests on local GGUF or sharded safetensors model files without loading weights into RAM.
   - `preflight_isolation_check()` and `is_loopback_endpoint()` validate container hardening posture, verify model SHA-256 pins, reject non-loopback/spoofed remote URLs, audit proxy environment variables, and emit a cryptographically hashed (and optionally HMAC-signed) pre-flight verification record.

2. **Pre-Inference Privacy & PII Engine (Pure R)**
   - `pii_config()`, `pii_detect()`, and `pii_redact()` deterministically identify and scrub emails, SSNs, US/international phone numbers, dates/DOBs, MRNs/student IDs, IPv4/IPv6 addresses, street addresses, **HIPAA Safe Harbor ages > 89 and US ZIP codes / 17 restricted 3-digit prefixes** (`hipaa_restricted_zip3()`), titled/role-cued/unlabeled person names (with Unicode homoglyph & zero-width obfuscator normalization and ReDoS-safe regexes), plus lab-supplied custom regexes, custom literal dictionaries, and clinical allowlists.
   - `pii_pseudonymize()` and `pii_reidentify()` implement deterministic keyed reversible pseudonymization using **RFC 5869 HKDF-SHA256 + HMAC-SHA256**, isolating raw mappings inside a separate **AES-256-CBC + HMAC-SHA256** (Encrypt-then-MAC with per-save random salts, fresh IVs, AAD binding, and constant-time MAC verification) local vault (`pii_vault_key()`, `pii_vault_save()`, `pii_vault_load()`) with owner-only (`0600`) permissions.
   - `pii_privacy_report()` produces aggregate pre-run coverage summaries by entity type without leaking raw sensitive values.

3. **Resumable Schema-Enforced Batch Extractor**
   - `extraction_schema()` and `schema_field()` declare strict scalar types (`character`, `integer`, `numeric`, `logical`, `enum`), nullability, numeric ranges, string lengths, and regex constraints, exporting standard JSON Schema (`as_json_schema()`).
   - `airgap_extract()` processes R data frames into strictly typed tibbles with mandatory pre-inference PII controls (`"redact"`, `"pseudonymize"`, or explicit `"verified_deidentified"`), delimited untrusted-record prompt-injection framing, **post-inference output PII leakage scanning** (`output_pii_action`), strict validation (`validate_extraction()`) with automated structured repair retries (`build_repair_prompt()`), and crash-resumable atomic per-row JSONL checkpointing (UTF-8 crash resilient, never storing raw input text).
   - Pluggable strictly-local runtimes: `runtime_ollama()`, `runtime_openai_local()` (for `llama.cpp` / `vLLM`, enforcing canonical loopback hosts and `noproxy = "*"`), and `runtime_mock()` (deterministic offline runtime with malformed-JSON retry and mid-batch crash simulation).

4. **Immutable IRB/HIPAA Audit Trail & Protocol Generator**
   - `audit_log_append()`, `audit_log_read()`, and `audit_log_verify()` maintain a tamper-evident SHA-256 hash-chained JSONL ledger (`GENESIS -> entry_1 -> entry_2 -> ...`) enforcing strict schema allowlists and active PII rejection (`airgap_audit_privacy_error`) so raw participant text never enters compliance logs.
   - `generate_irb_narrative()` renders ready-to-paste Markdown or Quarto IRB/HIPAA/FERPA Methods and Data-Security protocol boilerplate directly from verified runs and audit logs.

## Installation

```r
# Install the development version from GitHub:
# install.packages("remotes")
remotes::install_github("MarcusHarrisUConn/airgapllm")
```

## Quick Start

```r
library(airgapllm)
library(tibble)

# 1. Define a hardened, pinned air-gapped container spec
spec <- airgap_container_spec(
  backend = "ollama",
  image = "ollama/ollama",
  image_digest = paste0("sha256:", strrep("a", 64)),
  model_dir = "/srv/models/llama3",
  gpu = "nvidia"
)

# Generate reproducible Docker CLI / Compose / HPC Apptainer configs
emit_docker_run(spec)
emit_apptainer_def(spec)

# 2. Define a strict output schema
schema <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L),
  crisis_flag = schema_field("logical")
)

# 3. Run schema-enforced batch extraction with mandatory PII redaction & audit trail
notes <- tibble(
  note_id = c("N1", "N2"),
  text = c(
    "Patient: Jane Doe (MRN: 884210) emailed jane@clinic.org about mild insomnia.",
    "Follow-up session stable; coping skills practiced."
  )
)

audit_file <- tempfile(fileext = ".audit.jsonl")
ck_file <- tempfile(fileext = ".checkpoint.jsonl")

# Use runtime_ollama() or runtime_openai_local() in production; runtime_mock() offline
results <- airgap_extract(
  data = notes,
  text_col = "text",
  schema = schema,
  runtime = runtime_mock(seed = 42L),
  id_col = "note_id",
  pii_policy = "redact",
  checkpoint_path = ck_file,
  audit_log_path = audit_file,
  container_spec = spec
)

results

# 4. Verify cryptographic audit chain and render IRB protocol text
audit_log_verify(audit_file)
cat(generate_irb_narrative(audit_file, protocol_id = "IRB-2026-0412"))
```

## Documentation

- See [SECURITY.md](SECURITY.md) for the v0.2.0 adversarial red-team audit, SSRF/injection mitigations, and cryptographic vault specification.
- See [ARCHITECTURE.md](ARCHITECTURE.md) for the formal threat & privacy model, container hardening specification, and cryptographic audit log schema.
- Run `vignette("getting-started", package = "airgapllm")` for an end-to-end offline workflow walkthrough.
- Run `vignette("privacy-and-compliance", package = "airgapllm")` for custom PII dictionaries, encrypted reversible pseudonymization vaults, mid-batch crash recovery, and audit tamper detection.

## License

MIT © Marcus Harris
