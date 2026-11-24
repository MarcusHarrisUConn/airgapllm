# Changelog

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
