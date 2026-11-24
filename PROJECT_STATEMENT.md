# NA

## Project 4: `airgapllm` — IRB / HIPAA-Safe Offline Containerized Local AI Workbench

**Suggested GitHub Repo:** `airgapllm`  
**GitHub One-Liner:** *Verifiably offline, containerized local LLM
workflows with PII redaction, schema-enforced batch extraction, and
IRB/HIPAA audit trails in R.*  
**Topics:** `r-package`, `privacy`, `hipaa`, `irb`, `local-llm`,
`docker`, `apptainer`, `clinical-research`

### Project Statement

Behavioral, clinical, educational, and medical researchers sit on
extraordinarily rich unstructured text—therapy notes, student writing,
longitudinal EMA journals, patient narratives—that **cannot legally or
ethically be sent to external LLM APIs** under IRB, HIPAA, or FERPA
protocols. While open-weights models (`Llama`, `Qwen`, `Gemma`,
`Mistral`) can run locally on lab workstations or university HPC GPU
nodes, configuring air-gapped Docker or Apptainer GPU containers,
pinning exact model weights for reproducibility, stripping PII
pre-inference, enforcing strict structured outputs across thousands of
rows, and producing auditable compliance documentation remains far too
technical for most research labs.

`airgapllm` is a turnkey, privacy-first R workbench for **verifiably
offline local AI inference**. It generates and manages pinned,
network-isolated (`--network none`) local LLM containers via Docker or
HPC Apptainer, runs a deterministic pre-inference PII detection and
reversible pseudonymization layer in pure R, executes resumable
GPU-batched structured extraction directly on R data frames, and writes
immutable, PII-free cryptographic audit trails paired with
ready-to-paste IRB protocol documentation.

### Why Existing R Tools Aren’t Enough

- Existing local-LLM wrappers (`ollamar`, `rollama`) merely call a local
  HTTP port—they do not enforce network air-gapping, pin container/model
  digests, generate HPC GPU Apptainer recipes, redact PII pre-inference,
  checkpoint 50,000-row batches, or generate IRB/HIPAA audit logs.
- Researchers currently stitch together fragile Python scripts and
  ad-hoc regexes with zero formal guarantee that outbound network calls
  are disabled or that runs are reproducible.

### Core Architectural Pillars

1.  **Air-Gapped Container Lifecycle Manager:** Generates reproducible
    Docker (`--network none`, GPU passthrough, read-only rootfs) and HPC
    Apptainer `.def` configurations for `Ollama`, `llama.cpp`, and
    `vLLM`, verifying model weight SHA-256 digests and confirming
    network isolation prior to execution.
2.  **Pre-Inference Privacy & PII Engine:** Deterministic pure-R PII
    detector, redactor, and keyed reversible pseudonymizer covering
    names, emails, phone numbers, dates, MRNs/student IDs, locations,
    and lab-defined custom dictionaries—with explicit pre-run privacy
    coverage reports.
3.  **Resumable Schema-Enforced Batch Extractor:** Processes R data
    frames into strictly typed JSON/tibbles with automatic schema
    validation, structured repair retries on malformed generations,
    SQLite/parquet row-level checkpointing (crash-resumable), and
    throughput monitoring.
4.  **Immutable IRB/HIPAA Audit Trail & Protocol Generator:** Logs
    cryptographic run manifests (container digest, model SHA, prompt
    hash, decoding seed/temperature, isolation proof, redaction
    counts—never raw sensitive text) and renders standardized
    Methods/IRB Data-Security narrative snippets.

### v1 Definition of Done

- Deterministic PII redaction/pseudonymization engine with strong
  edge-case unit test coverage.
- Docker (`--network none`) and HPC GPU Apptainer config generators +
  pre-flight isolation verifier.
- Crash-resumable, schema-validated batch extraction engine working
  cleanly against both local HTTP endpoints and a built-in deterministic
  offline mock runtime.
- Immutable JSONL audit logger, IRB boilerplate generator, comprehensive
  `testthat` suite, vignettes, and clean `R CMD check`.

### New-Conversation Handoff Block

``` text
We are starting a new flagship, CRAN-grade R package in this repository: `airgapllm` — an IRB/HIPAA-safe, verifiably offline, containerized local AI workbench for sensitive research data in R.

Project mission: Enable clinical, behavioral, educational, and health researchers to run reproducible local LLMs on sensitive text without external API leakage:
1. Air-gapped container manager generating pinned Docker (`--network none`, read-only filesystem, GPU options) and HPC GPU Apptainer configs for `Ollama` / `llama.cpp` / `vLLM`, with model-weight SHA digest pinning and isolation pre-flight checks.
2. Pure-R pre-inference PII detection, redaction, and reversible pseudonymization pipeline (names, emails, phones, dates, IDs, custom dictionaries) with redaction summaries.
3. Crash-resumable, schema-enforced batch extraction from R data frames into typed tibbles (strict schema validation, structured retry/repair, disk checkpointing).
4. Immutable PII-free cryptographic audit trail + IRB/Methods data-security boilerplate generator.
5. Full deterministic mock/offline runtime so 100% of `testthat` tests pass cleanly on macOS without a GPU or live container.

Please start by inspecting this repo, proposing the threat/privacy model, modular architecture (`ARCHITECTURE.md`), and phased implementation plan, and then we will build iteratively to full tests, vignettes, and a clean `R CMD check`.
```
