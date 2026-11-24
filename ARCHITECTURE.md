# airgapllm Architecture & Threat Model

## 1. Mission & Design Philosophy

`airgapllm` is a privacy-first, CRAN-grade R workbench for running local
open-weights Large Language Models (`Ollama`, `llama.cpp`, `vLLM`) on
sensitive human-subjects data (clinical notes, therapy transcripts, EMA
journals, student essays, patient narratives) under IRB, HIPAA, and
FERPA governance.

Every architectural decision follows four invariants:

1.  **Fail-Closed Network Isolation:** Remote endpoints are rejected
    before any sensitive text is touched. Generated container
    specifications enforce `--network none`, read-only root filesystems,
    dropped Linux capabilities, and pinned image SHA-256 digests.
2.  **Pre-Inference De-Identification:** Sensitive text passes through a
    deterministic pure-R PII redaction or keyed HMAC-SHA256
    pseudonymization gate prior to prompt construction (unless the
    researcher explicitly attests `"verified_deidentified"`).
3.  **Zero-PII-Leakage Persistence:** Checkpoints, privacy reports,
    audit trails, and IRB protocol outputs are strictly barred from
    storing raw input text, raw model prompts, or raw PII values.
    Re-identification vaults are isolated and encrypted at rest
    (AES-256-CBC + HMAC-SHA256).
4.  **Reproducible, Crash-Resumable Execution:** Model weights,
    container images, schemas, prompt templates, and decoding
    hyperparameters are hashed and logged into a tamper-evident SHA-256
    hash-chained JSONL ledger, while row-level atomic JSONL
    checkpointing enables seamless crash recovery across large datasets.

------------------------------------------------------------------------

## 2. Explicit Threat & Privacy Model

### 2.1 Assets Protected

- **Protected Health Information (PHI) / Personally Identifiable
  Information (PII):** Direct identifiers (names, emails, phones, SSNs,
  dates/DOBs, MRNs/student IDs, IP addresses, street addresses, custom
  lab dictionaries) in research text corpora.
- **Pseudonymization Vault & Secret Keys:** Mapping tables enabling
  reversible de-identification.
- **Model Integrity & Experimental Reproducibility:** Weight binaries
  (GGUF / safetensors), container images, prompt templates, schemas, and
  random seeds.
- **Compliance Evidence:** Tamper-evident audit logs and pre-flight
  isolation attestations reviewed by IRBs and data security officers.

### 2.2 Threat Matrix & Mitigations

| Threat ID | Threat Scenario | Attack Vector / Failure Mode | `airgapllm` Mitigation |
|:---|:---|:---|:---|
| **T1: Network Exfiltration** | Sensitive text sent to external APIs or telemetry endpoints | Accidental remote URL (`api.openai.com`), container outbound access, corporate HTTP proxy hijacking localhost requests, Hugging Face Hub telemetry | Hard loopback/Unix-socket URL validation ([`is_loopback_endpoint()`](https://marcusharrisphd.com/airgapllm/reference/is_loopback_endpoint.md)) rejecting userinfo tricks, non-loopback IPs, `0.0.0.0`, and remote hostnames; `httr2` proxy bypass (`noproxy = "*"`); `--network none` + `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `DO_NOT_TRACK=1`, `OLLAMA_NOHISTORY=1`; [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md) gate before inference. |
| **T2: Weight & Image Tampering** | Silent container tag mutation (`:latest`) or corrupted/trojanized model weights | Pulling mutable Docker tags or unverified GGUF/safetensors files | Mandatory pinned `sha256:<64-hex>` image digests in [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md); streaming SHA-256 file and directory-manifest verification via [`verify_model_digest()`](https://marcusharrisphd.com/airgapllm/reference/verify_model_digest.md); digests persisted in every audit entry. |
| **T3: Container Breakout / Persistence** | Compromised inference runtime modifying container filesystem or retaining sensitive prompts on disk | Writable rootfs, privileged capabilities, default root execution, uncleaned temp dirs | `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, read-only model mounts (`:ro`), bounded `noexec,nosuid` `/tmp` tmpfs, Apptainer `--containall --no-home --net --network none`. |
| **T4: PII Leakage into Prompts** | Unredacted names, MRNs, SSNs, or emails sent to model context window (and potentially echoed or memorized in KV cache/logs) | Forgetting manual de-identification prior to batch extraction | Mandatory `pii_policy` parameter in [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md) defaulting to `"redact"` (or `"pseudonymize"` with HMAC-SHA256 tokens; `"verified_deidentified"` requires explicit opt-in and is recorded in the audit trail). |
| **T5: PII Leakage into Logs, Reports & Console** | Sensitive strings captured in audit logs, privacy summaries, checkpoints, or error tracebacks | Logging full prompts/responses, printing vault dictionaries, attaching raw strings to error metadata | Strict schema allowlist + forbidden-key rejection (`airgap_audit_privacy_error`) + active PII scanning on audit metadata; privacy reports emit aggregate counts only; `print.airgap_pii_vault()` masks all mappings; checkpoints omit raw input text and store only `input_sha256` and validated typed outputs. |
| **T6: Vault Compromise** | Re-identification mapping file exposed on shared lab storage | Plaintext CSV/JSON mapping file stored next to processed data | Separate vault serialization ([`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md)) with AES-256-CBC encryption + HMAC-SHA256 (Encrypt-then-MAC) authentication tag, random 128-bit IV, and `0600` filesystem permissions. |
| **T7: Mid-Batch Crash / Partial Corruption** | GPU OOM, HPC Slurm walltime preemption, or workstation power loss at row 12,400 of 50,000 | Reprocessing hours of completed work or corrupting an entire monolithic output file | Append-only atomic per-row JSONL checkpointing (`checkpoint_path`) with header compatibility verification (`schema_digest`, `prompt_template_hash`, `pii_policy`); automatic recovery/truncation of partial trailing lines on resume; completed rows skipped deterministically. |
| **T8: Malformed / Hallucinated Model Output** | Local 7B–8B quantized models emit broken JSON, wrong types, or out-of-range enum labels | Silent `NA` coercion or pipeline crash | Strict [`extraction_schema()`](https://marcusharrisphd.com/airgapllm/reference/extraction_schema.md) validator ([`validate_extraction()`](https://marcusharrisphd.com/airgapllm/reference/validate_extraction.md)) rejecting extra keys, type mismatches, non-nullable nulls, and constraint violations, paired with bounded automatic structured repair retry prompts ([`build_repair_prompt()`](https://marcusharrisphd.com/airgapllm/reference/build_repair_prompt.md)). |
| **T9: Post-Hoc Audit Tampering** | Retrospective editing or deletion of compliance log rows | Plaintext log files altered after an incident | Cryptographic SHA-256 hash chain (`GENESIS -> entry_1 -> entry_2 -> ...`) verified end-to-end by [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md), detecting field edits, deletions, insertions, or reordering. |

### 2.3 Explicit Out-of-Scope / Trust Boundaries

- `airgapllm` assumes the host OS kernel, Docker/Apptainer daemon, and
  physical workstation/HPC node are trusted and administered under
  institutional security controls.
- Pure-R deterministic PII detection combines high-precision pattern
  matchers, capitalization/title heuristics, and lab-supplied custom
  dictionaries; because no regex/heuristic system guarantees 100% recall
  on arbitrary free text, researchers should combine domain custom
  dictionaries, review
  [`pii_privacy_report()`](https://marcusharrisphd.com/airgapllm/reference/pii_privacy_report.md),
  and rely on the air-gapped container as defense-in-depth.

------------------------------------------------------------------------

## 3. Modular Package Architecture

    R/
    ├── airgapllm-package.R   # Package documentation & shared imports
    ├── utils.R               # Canonical JSON, SHA-256/HMAC helpers, timestamps, error classes
    ├── container.R           # Pillar 1: airgap_container_spec(), Docker/Compose/Apptainer emitters,
    │                         #           verify_model_digest(), is_loopback_endpoint(),
    │                         #           preflight_isolation_check()
    ├── pii.R                 # Pillar 2: pii_config(), pii_detect(), pii_redact(),
    │                         #           pii_pseudonymize(), pii_reidentify(),
    │                         #           pii_vault_key/save/load(), pii_privacy_report()
    ├── schema.R              # Pillar 3a: schema_field(), extraction_schema(),
    │                         #            as_json_schema(), validate_extraction(),
    │                         #            build_repair_prompt()
    ├── runtime.R             # Pillar 3b: runtime_ollama(), runtime_openai_local(),
    │                         #            runtime_mock(), runtime invocation dispatch
    ├── extract.R             # Pillar 3c: airgap_extract(), atomic JSONL checkpoint manager,
    │                         #            result accessors (extraction_manifest, etc.)
    ├── audit.R               # Pillar 4a: audit_log_append(), audit_log_read(),
    │                         #            audit_log_verify(), zero-PII enforcement
    └── irb.R                 # Pillar 4b: generate_irb_narrative() (Markdown & Quarto)

### Data Flow Pipeline

    Raw Data Frame (sensitive text)
            │
            ▼
    [1] Pre-Flight Isolation Gate (preflight_isolation_check)
        - Container hardening flags (--network none, --read-only, --cap-drop ALL, pinned digest)
        - Model weight SHA-256 verification (verify_model_digest)
        - Strict loopback / unix-socket / mock endpoint check + proxy check
            │ (FAIL => abort before touching text)
            ▼
    [2] Pre-Inference Privacy Gate (pii_redact / pii_pseudonymize)
        - Deterministic priority-ordered span detection & overlap resolution
        - Aggregate-only pii_privacy_report()
        - Optional HMAC-SHA256 pseudonymization -> separate encrypted vault (AES-256-CBC + HMAC)
            │ (Only sanitized text proceeds)
            ▼
    [3] Resumable Batch Extraction Loop (airgap_extract)
        - Load/verify JSONL checkpoint header & skip completed row IDs
        - For each pending row:
            Prompt Render -> Local Runtime (Ollama / llama.cpp / vLLM / Mock)
            -> Strict Schema Validation -> (on error: Structured Repair Retry up to max_retries)
            -> Atomic JSONL Checkpoint Append (no raw text stored)
            │
            ▼
    [4] Typed Tibble Assembly + Audit Trail + IRB Protocol
        - Strict R column types (character, integer, numeric, logical, enum)
        - Optional local re-identification of output columns via vault
        - Hash-chained PII-free JSONL entry (audit_log_append / audit_log_verify)
        - Methods / IRB boilerplate generation (generate_irb_narrative)

------------------------------------------------------------------------

## 4. Container Hardening Specification

### 4.1 Docker CLI (`emit_docker_run`) & Compose (`emit_docker_compose`)

All generated specifications enforce: - **Network:** `--network none`
(default strict airgap; optional `internal: true` Compose network with
`127.0.0.1` loopback binding when host-to-container HTTP is needed). -
**Filesystem:** `--read-only`, model directory mounted read-only
(`-v <model_dir>:/models:ro`), bounded tmpfs
(`--tmpfs /tmp:rw,noexec,nosuid,size=512m`). - **Linux Security:**
`--cap-drop ALL`, `--security-opt no-new-privileges:true`, optional
non-root `--user`. - **Image Pinning:** `<image>@sha256:<64-hex>`
(mutable tags without digest are rejected by preflight). - **Offline
Telemetry Suppression:** `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`,
`DO_NOT_TRACK=1`, `OLLAMA_NOHISTORY=1`,
`OLLAMA_HOST=127.0.0.1:<port>`. - **GPU Passthrough (Optional):**
`--gpus <devices>` (NVIDIA) or `--device /dev/kfd --device /dev/dri`
(AMD ROCm).

### 4.2 HPC Apptainer (`emit_apptainer_def`)

Generates a reproducible `.def` recipe pinning
`From: <image>@sha256:...`, injecting offline `%environment` variables,
provenance `%labels` (including `spec_digest` and `model_digest`),
backend `%runscript`, and documented runtime invocation flags:

``` bash
apptainer run --containall --no-home --net --network none [--nv|--rocm] \
  --bind <model_dir>:/models:ro <image>.sif
```

------------------------------------------------------------------------

## 5. Immutable IRB / HIPAA Audit Log Schema (v1.0)

Stored as newline-delimited JSON (`.jsonl`), one object per line, sorted
keys for canonical hashing:

``` json
{
  "container_backend": "ollama",
  "container_image_digest": "sha256:...",
  "container_spec_digest": "sha256:...",
  "decoding_params": {
    "max_tokens": 1024,
    "seed": 42,
    "temperature": 0,
    "top_p": 1
  },
  "endpoint_class": "loopback",
  "entry_hash": "sha256:...",
  "event_type": "extraction_run",
  "isolation_status": "PASS",
  "model_digest": "sha256:...",
  "model_name": "llama3.1:8b-instruct-q4_K_M",
  "network_mode": "none",
  "os_info": "Darwin 23.x arm64",
  "package_version": "0.1.0",
  "pii_config_digest": "sha256:...",
  "pii_counts": {
    "date": 14,
    "email": 3,
    "mrn_id": 12,
    "person_name": 27
  },
  "pii_policy": "redact",
  "preflight_hash": "sha256:...",
  "prev_hash": "GENESIS",
  "prompt_template_hash": "sha256:...",
  "r_version": "4.6.1",
  "row_counts": {
    "failed": 0,
    "processed": 500,
    "resumed": 0,
    "succeeded": 500,
    "total": 500,
    "total_retries": 4
  },
  "run_id": "run_20261123T150000Z_a1b2c3d4",
  "schema_digest": "sha256:...",
  "schema_version": "1.0",
  "seq": 1,
  "timestamp": "2026-11-23T15:00:00Z"
}
```

### Cryptographic Chain Rule

- For `seq == 1`: `prev_hash = "GENESIS"`.
- For `seq > 1`: `prev_hash = entry[seq - 1].entry_hash`.
- `entry_hash = "sha256:" || SHA256(canonical_json(entry without entry_hash))`.
- Canonical JSON sorts all object keys lexicographically at every
  nesting depth and serializes with `auto_unbox = TRUE`,
  `null = "null"`, `digits = NA`.

### Zero-PII Enforcement Rule

- Any entry containing forbidden raw-content keys (`text`, `raw_text`,
  `input`, `prompt`, `response`, `output`, `vault`, `matches`,
  `pii_values`, etc.) or triggering
  [`pii_detect()`](https://marcusharrisphd.com/airgapllm/reference/pii_detect.md)
  on free-text metadata is immediately rejected with an
  `airgap_audit_privacy_error` prior to disk write.
