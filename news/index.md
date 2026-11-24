# Changelog

## airgapllm 0.5.0

### Independent Peer Red-Team Security, Privacy & Robustness Hardening

Addresses all **21 confirmed findings** (2 CRITICAL, 9 HIGH, 7 MEDIUM, 3
LOW) from the independent peer red-team security audit, backed by
permanent regression tests in `tests/testthat/test-peer-redteam.R`:

#### Critical Fixes

- **Eliminated `cli` Glue Expression Injection / RCE (`C-01`)**: Escaped
  dynamic diagnostic strings across all untrusted-input
  [`cli::cli_abort()`](https://cli.r-lib.org/reference/cli_abort.html)
  call sites (`R/audit.R`, `R/irb.R`, `R/workflow.R`, `R/runtime.R`,
  `R/container.R`, `R/pii.R`) via centralized `escape_cli_braces()`,
  preventing arbitrary R code execution from tampered audit logs,
  malicious endpoint URLs, invalid model paths, metadata keys, or
  malformed regexes.
- **Closed Audit Log & IRB Compliance Packet PHI Leakage (`C-02`)**:
  Enforced finite non-negative integer validation on `row_counts`,
  `pii_counts`, and `output_pii_leaks`, strict ISO-8601 UTC `timestamp`
  validation, and full built-in PII scanning across `decoding_params`,
  `run_id`, `event_type`, `model_name`, and all scalar string audit
  fields. Upgraded
  [`export_irb_compliance_packet()`](https://marcusharrisphd.com/airgapllm/reference/export_irb_compliance_packet.md)
  to pre-scan protocol header fields and scan **every** exported
  artifact (including `irb_protocol_narrative.md`,
  `irb_protocol_narrative.qmd`, container specs, and
  `packet_manifest.json`) across all built-in direct PII classes before
  setting `zero_pii_verified = TRUE`.

#### High-Severity Security & Privacy Fixes

- **Forged Pseudonym Token Detection & Nonce Sentinels (`H-01`)**:
  `scan_and_handle_output_pii()` now verifies `<<TYPE_HEX>>` tokens
  strictly against active vault token allowlists, flagging forged
  hex-digit exfiltration tokens as `forged_pseudonym_token`, and
  protects genuine tokens with per-call 64-bit random nonces
  (`__AGVTOK_<nonce>_...__`) and single-pass restoration to prevent
  placeholder collisions.
- **Protected Container Offline/Loopback Environment Controls
  (`H-02`)**: Blocked overriding `HF_HUB_OFFLINE`,
  `TRANSFORMERS_OFFLINE`, `HF_DATASETS_OFFLINE`, `DO_NOT_TRACK`,
  `OLLAMA_NOHISTORY`, `OLLAMA_HOST`, `OLLAMA_MODELS`, and proxy
  variables (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`/etc.) in
  `airgap_container_spec(env = ...)`, re-validated in
  `build_container_env()`, and added a required
  `container_env_isolation` check in
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md).
- **Vault Encryption Downgrade Defense (`H-03`)**:
  [`pii_vault_load()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_load.md)
  now accepts `require_encrypted = !is.null(key)` and aborts with
  `airgap_vault_error` if an unencrypted JSON vault is encountered when
  a decryption `key` is supplied or `require_encrypted = TRUE`.
- **Symlink Write Confinement & Pre-Write `0600` Permissions (`H-04`)**:
  Added `assert_safe_write_target()` across
  [`export_irb_compliance_packet()`](https://marcusharrisphd.com/airgapllm/reference/export_irb_compliance_packet.md),
  [`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md),
  `pii_vault_rotate_key(backup = TRUE)`,
  [`audit_log_append()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_append.md),
  `airgap_extract(checkpoint_path = ...)`,
  `generate_irb_narrative(file = ...)`, and container emitters, ensuring
  symlink targets can never be overwritten and temporary vault/backup
  files receive `0600` permissions before bytes are written.
- **Model Digest Hidden-File & Parent-Symlink Confinement (`H-05`)**:
  [`verify_model_digest()`](https://marcusharrisphd.com/airgapllm/reference/verify_model_digest.md)
  now enumerates hidden dotfiles (`all.files = TRUE, no.. = TRUE`) and
  walks all parent directory components to block parent-directory
  symlinks even when `root_dir = NULL`.
- **Unicode Combining-Mark, ALL-CAPS EHR & Accented Name PII Coverage
  (`H-06`)**: Extended `canonicalize_pii_text()` to strip Unicode
  combining diacritics and transliterate Latin accented letters with
  exact original span mapping; added case-insensitive clinical
  title/role matching and ALL-CAPS role-prefixed name detection
  (`PATIENT: JOHN DOE`, `DR. JANE DOE`, `ATTENDING ROBERT MILLER`).
- **Pre-Inference `prompt_template` PHI Gate (`H-07`)**:
  [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
  and
  [`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md)
  now scan supplied prompt templates for raw PII and reject pre-rendered
  templates embedding unsanitized input rows when
  `pii_policy != "verified_deidentified"`.
- **Injective $`k`$-Anonymity Keys & Fail-Closed `include_na = FALSE`
  (`H-08`)**: Replaced `\x1f`/`"<NA>"` equivalence keys with strictly
  injective length-prefixed encoding (`N:` vs `V<bytes>:<value>`);
  prevented `NA`-QI rows from escaping suppression/masking under
  `include_na = FALSE`; rejected `mask_value = NA` with
  `include_na = FALSE`; failed closed when all non-empty rows are
  excluded; and added `airgap_anonymity_warning` whenever
  post-anonymization targets remain unmet.
- **Checkpoint Model Identity, Input-Drift Verification & Zero-PHI Error
  Hygiene (`H-09`)**: `checkpoint_load()` now verifies `header$model`
  matches the active runtime model; resume logic verifies per-row
  `input_sha256` against sanitized input text; and
  [`validate_extraction()`](https://marcusharrisphd.com/airgapllm/reference/validate_extraction.md)
  omits untrusted raw LLM extra keys and raw enum values from persisted
  `.error` messages.

#### Medium & Low Reliability & Interoperability Fixes

- **Consensus Token Allowlisting & Integrity (`M-01`, `M-02`)**:
  Propagated active vault tokens into
  [`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md)
  inner passes so genuine all-digit pseudonym tokens (e.g.,
  `<<PAT_0123456789>>`) are preserved cleanly; rejected duplicate
  `prompt_templates` names and schema field collisions with `id_col` or
  consensus columns; returned `NA_real_` agreement when fewer than 2
  passes succeed; and eliminated `Inf` overflow on wide numeric bounds
  (`[-1e308, 1e308]`).
- **Uniform Finite Integer Validation (`M-03`)**: Centralized
  `assert_scalar_int()` rejecting `Inf`, `NaN`, non-integers, and
  out-of-range doubles across all numeric/integer entry points.
- **Chunker Progress & Exact Character Overlap (`M-04`)**: Enforced
  `min_cut >= overlap_chars + 1L` in
  [`chunk_clinical_texts()`](https://marcusharrisphd.com/airgapllm/reference/chunk_clinical_texts.md)
  to prevent nested duplicate-chunk explosions and gated word-boundary
  overlap snapping to non-character split modes.
- **IPv6 `[::1]` Proxy Audit & Container Flag Hardening (`M-05`)**:
  Updated `detect_outbound_proxies()` to require `::1` in `NO_PROXY`
  when targeting `[::1]`; blocked `--trust-remote-code`,
  `--download-dir`, and leading-dash `model_dir` paths.
- **Single-Pass
  [`pii_reidentify()`](https://marcusharrisphd.com/airgapllm/reference/pii_reidentify.md)
  & Consensus IRB Parity (`M-06`)**: Upgraded
  [`pii_reidentify()`](https://marcusharrisphd.com/airgapllm/reference/pii_reidentify.md)
  to single-pass left-to-right token replacement; added
  `airgap_consensus` support to
  [`export_irb_compliance_packet()`](https://marcusharrisphd.com/airgapllm/reference/export_irb_compliance_packet.md)
  and `"consensus_extraction_run"` selection in
  [`generate_irb_narrative()`](https://marcusharrisphd.com/airgapllm/reference/generate_irb_narrative.md).
- **Hardware Auto-Tuner OOM Warnings & Input Validation (`M-07`)**:
  Added `recommended$feasible` flag + `airgap_hardware_warning` on
  infeasible VRAM fallback, strictly capped `container_memory_limit` at
  physical `ram_gb`, and hardened `corpus_size`, `preview_n`, and
  `preview_chars` checks.
- **Prompt-Sensitive Mock Variance, Multiline Addresses & Delimiter
  Sanitization (`L-01`, `L-02`, `L-03`)**: Mixed prompt template
  instruction hashes into
  [`runtime_mock()`](https://marcusharrisphd.com/airgapllm/reference/runtime_mock.md)
  deterministic outputs for realistic multi-prompt consensus variance;
  extended `street_address` regex across newline-separated
  city/state/ZIP lines; rejected shell metacharacters in `unix:///`
  paths; and broadened `neutralize_prompt_delimiters()` to match
  whitespace/attribute tag variants.

## airgapllm 0.4.0

### New Research-Workflow Capabilities

- **Quasi-Identifier & k-Anonymity / l-Diversity Risk Auditor
  (`R/anonymity.R`)**:
  - Added
    [`assess_reidentification_risk()`](https://marcusharrisphd.com/airgapllm/reference/assess_reidentification_risk.md)
    quantifying equivalence class distributions, minimum/median $`k`$,
    sample uniques, $`k`$-anonymity violations, prosecutor and
    journalist re-identification risk metrics, and optional distinct
    $`l`$-diversity for sensitive outcomes—never logging raw participant
    values.
  - Added
    [`apply_k_anonymity()`](https://marcusharrisphd.com/airgapllm/reference/apply_k_anonymity.md)
    supporting safe row suppression (`"suppress_rows"`) and progressive
    rare-class masking (`"mask_rare"`, automatically absorbing smallest
    residual classes so masked fallback groups strictly satisfy `k_min`
    and `l_min`), returning privacy-safe tables alongside before/after
    risk reductions.
- **Multi-Pass Consensus & Self-Consistency Extraction
  (`R/consensus.R`)**:
  - Added
    [`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md)
    running deterministic multi-pass extractions across multiple random
    seeds and/or prompt variants (including full crossed
    `seeds x prompt_templates` designs), aggregating categorical/logical
    fields by majority vote (`tie_policy = c("first", "na")`) and
    numeric/integer fields by median, trimmed mean, or mean.
  - Added
    [`consensus_passes()`](https://marcusharrisphd.com/airgapllm/reference/consensus_accessors.md)
    (long-format pass table directly compatible with psychometric
    generalizability / reliability studies with zero hard dependencies)
    and
    [`consensus_diagnostics()`](https://marcusharrisphd.com/airgapllm/reference/consensus_accessors.md)
    (per-field agreement, unanimity, and tie counts), with seamless
    integration into
    [`extraction_manifest()`](https://marcusharrisphd.com/airgapllm/reference/extraction_accessors.md),
    [`audit_log_append()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_append.md),
    and
    [`generate_irb_narrative()`](https://marcusharrisphd.com/airgapllm/reference/generate_irb_narrative.md).
- **Hardware-Aware Auto-Tuner & Runtime Benchmarker (`R/benchmark.R`)**:
  - Added
    [`recommend_runtime_config()`](https://marcusharrisphd.com/airgapllm/reference/recommend_runtime_config.md)
    selecting OOM-safe open-weights parameter tiers, quantizations,
    context windows, batch sizes, KV precisions, and hardened container
    memory limits for workstation GPUs, multi-GPU HPC nodes, and
    CPU-only hosts.
  - Added
    [`benchmark_local_runtime()`](https://marcusharrisphd.com/airgapllm/reference/benchmark_local_runtime.md)
    profiling pilot throughput (`rows/sec`), p50/p95 latency, schema
    validation success rate, repair retry rate, and projected
    full-corpus ETA cleanly on local or mock runtimes.

### Coverage-Driven Bug Fixes & Documentation

- Conducted a comprehensive `covr` audit raising package line coverage
  from 89.3% to **\>94%** and resolving five latent edge cases:
  - Fixed 0-byte pre-existing checkpoint files failing to initialize a
    header record before appending rows in
    [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md).
  - Hardened output PII masking sentinels when combining
    `pii_policy = "pseudonymize"` with `output_pii_action = "redact"`.
  - Added malformed tail guards to
    `audit_log_append(..., verify_existing = FALSE)`.
  - Removed unreachable dead branches in `resolve_overlapping_spans()`.
  - Suppressed spurious base PCRE compilation warnings before throwing
    structured validation errors on invalid custom regexes in
    [`schema_field()`](https://marcusharrisphd.com/airgapllm/reference/schema_field.md)
    and
    [`pii_config()`](https://marcusharrisphd.com/airgapllm/reference/pii_config.md).
- Added a fifth executable vignette
  (`vignettes/consensus-and-kanonymity.Rmd`), updated the standalone PDF
  Field Guide, `pkgdown` reference site, and `README.md`.

## airgapllm 0.3.0

### Production Clinical & HPC Workflow Capabilities

- Added
  [`chunk_clinical_texts()`](https://marcusharrisphd.com/airgapllm/reference/chunk_clinical_texts.md)
  for deterministic paragraph-, sentence-, or character-aligned
  overlapping chunking of long therapy transcripts and interviews with
  preserved `doc_id`, `chunk_id`, `chunk_index`, and character offset
  provenance.
- Added
  [`pii_audit_dataframe()`](https://marcusharrisphd.com/airgapllm/reference/pii_audit_dataframe.md)
  for non-destructive pre-inference privacy dry-runs producing aggregate
  entity coverage, high-PII-density row flags, HIPAA Safe Harbor and
  Unicode advisories, and strictly redacted preview snippets containing
  zero raw PII.
- Added
  [`estimate_vram_requirements()`](https://marcusharrisphd.com/airgapllm/reference/estimate_vram_requirements.md)
  to estimate total GPU VRAM (model weights + GQA KV-cache + runtime
  overhead) across parameter counts, quantizations (`Q4_K_M`, `Q6_K`,
  `Q8_0`, `FP16`), context windows, batch sizes, and GPU hardware tiers.
- Added
  [`pii_vault_rotate_key()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_rotate_key.md)
  for atomic in-place or target-path master key rotation of encrypted
  `airgapllm_vault_v2` vaults with fresh HKDF-SHA256 salts, fresh IVs,
  and preserved historical token mappings.
- Added
  [`export_irb_compliance_packet()`](https://marcusharrisphd.com/airgapllm/reference/export_irb_compliance_packet.md)
  to assemble a self-contained, strictly PII-free, SHA-256-sealed
  IRB/HIPAA review directory containing the verified audit log,
  pre-flight attestation, hardened container definitions,
  Markdown/Quarto IRB narratives, and `packet_manifest.json`.
- Added bundled 100% fictional teaching dataset `synthetic_notes`
  (`data/synthetic_notes.rda`) spanning synthetic clinical therapy
  notes, EMA journals, student writing, HIPAA Safe Harbor cases, and a
  multi-paragraph transcript.
- Hardened
  [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
  and PII helpers with safe Latin-1 / Windows-1252 to UTF-8
  normalization (`normalize_text_utf8()`), graceful 0-row data frame
  handling, and actionable checkpoint schema/prompt/policy mismatch
  diagnostics.

### CRAN Readiness, Documentation & Website

- Expanded to 4 executable offline vignettes: `getting-started`,
  `privacy-and-compliance`, `irb-hipaa-compliance-walkthrough`, and
  `hpc-gpu-deployment`.
- Added package-level documentation
  ([`?airgapllm`](https://marcusharrisphd.com/airgapllm/reference/airgapllm-package.md)),
  `inst/CITATION`, runnable example scripts in `inst/examples/`,
  standalone PDF Field Guide (`inst/guides/airgapllm-guide.Rmd`),
  `inst/WORDLIST` for zero-misspelling checks, `cran-comments.md`,
  `_pkgdown.yml`, and GitHub Actions CI workflows (`R-CMD-check.yaml`,
  `pkgdown.yaml`).

## airgapllm 0.2.0

### Security Hardening & Red-Team Upgrades

- Added centralized security, cryptography, and sanitization module
  (`R/security.R`) with constant-time byte comparisons
  (`constant_time_equal()`), RFC 5869 HKDF-SHA256 key derivation
  (`hkdf_sha256()`), strict SSRF/URL parsing, container injection
  guards, symlink/path confinement, and Unicode canonicalization.
- **Air-Gap SSRF & Proxy Hardening**:
  [`is_loopback_endpoint()`](https://marcusharrisphd.com/airgapllm/reference/is_loopback_endpoint.md)
  and
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md)
  now reject CRLF/control characters, backslashes, URL fragments,
  percent-encoded authorities, IPv6-mapped IPv4
  (`[::ffff:169.254.169.254]`, `[::ffff:7f00:1]`), non-canonical IPv6,
  octal/hex/decimal/shorthand IPv4 notations (`0177.0.0.1`,
  `2130706433`, `0x7f000001`, `127.1`), and DNS-rebinding tricks.
  [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md)
  now audits all `*_proxy` environment variables case-insensitively and
  fails closed by default (`strict_proxy = TRUE`) when outbound proxies
  lack explicit `127.0.0.1` and `localhost` entries in `NO_PROXY`.
- **Container & Symlink Injection Defense**:
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md),
  [`emit_docker_run()`](https://marcusharrisphd.com/airgapllm/reference/emit_docker_run.md),
  [`emit_docker_compose()`](https://marcusharrisphd.com/airgapllm/reference/emit_docker_compose.md),
  and
  [`emit_apptainer_def()`](https://marcusharrisphd.com/airgapllm/reference/emit_apptainer_def.md)
  now block newline/shell/YAML/Apptainer `%post` injection, bind-mount
  `:` option injection, `..` traversal, dangerous linker/shell env vars
  (`LD_PRELOAD`, `BASH_ENV`), and security-override flags
  (`--privileged`, `--cap-add`, non-loopback `--host`), and POSIX-quote
  all Apptainer `%runscript` arguments.
  [`verify_model_digest()`](https://marcusharrisphd.com/airgapllm/reference/verify_model_digest.md)
  now rejects symbolic links by default (`allow_symlinks = FALSE`) and
  enforces canonical `root_dir` confinement.
- **Vault v2 Cryptography**: Upgraded
  [`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md)
  and
  [`pii_vault_load()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_load.md)
  to `airgapllm_vault_v2` using RFC 5869 HKDF-SHA256 domain-separated
  keys with per-save random 128-bit salts, fresh random 128-bit IVs,
  full AAD header authentication, constant-time Encrypt-then-MAC
  verification strictly before decryption, and uniform error messages
  eliminating padding oracles (while retaining backward-compatible
  constant-time verification for v1 vaults).
- **HIPAA Safe Harbor, Unicode Defense & ReDoS Hardening**:
  - Added
    [`hipaa_restricted_zip3()`](https://marcusharrisphd.com/airgapllm/reference/hipaa_restricted_zip3.md)
    and built-in `"age_over_89"` and `"zip_code"` HIPAA Safe Harbor
    entity detectors (covering ages \> 89, 5-digit/ZIP+4 postal codes,
    and the 17 HHS restricted 3-digit ZIP prefixes).
  - Added index-preserving Unicode canonicalization defeating zero-width
    obfuscators (`U+200B`, `U+FEFF`, `U+00AD`), Unicode dashes,
    fullwidth ASCII, and Cyrillic/Greek homoglyphs.
  - Hardened all PII regular expressions with bounded quantifiers, fixed
    sentence-ending period lookahead for emails, and upgraded overlap
    resolution and span replacement to O(M log M + N).
- **Prompt-Injection Framing, Output PII Scan & Resilient Checkpoints**:
  - Framed untrusted research text inside `<UNTRUSTED_RESEARCH_RECORD>`
    delimiters with tag-breakout neutralization and hardened local
    runtime system prompts.
  - Added post-inference output PII leakage scanning
    (`output_pii_action = c("redact", "error", "warn", "none")`) in
    [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md),
    recording integer `output_pii_leaks` counts in manifests and audit
    logs.
  - Hardened JSONL checkpoint and audit readers
    (`read_jsonl_raw_lines()`) against truncated UTF-8 and NUL byte
    corruption, scrubbed PII from persisted checkpoint error messages,
    and switched
    [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md)
    to constant-time digest checks.
- Added `SECURITY.md` documenting all v0.2.0 red-team findings and
  mitigations, plus `tests/testthat/test-adversarial-security.R`.

## airgapllm 0.1.0

- Initial CRAN-grade release providing the four core pillars: air-gapped
  Docker/Compose/Apptainer container lifecycle manager, pure-R
  pre-inference PII redaction & HMAC-SHA256 pseudonymization engine,
  crash-resumable schema-enforced batch extractor with local HTTP and
  deterministic mock runtimes, and tamper-evident SHA-256 hash-chained
  JSONL audit trail with IRB/HIPAA protocol narrative generator.
