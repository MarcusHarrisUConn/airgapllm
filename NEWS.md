# airgapllm 0.2.0

## Security Hardening & Red-Team Upgrades

* Added centralized security, cryptography, and sanitization module (`R/security.R`) with constant-time byte comparisons (`constant_time_equal()`), RFC 5869 HKDF-SHA256 key derivation (`hkdf_sha256()`), strict SSRF/URL parsing, container injection guards, symlink/path confinement, and Unicode canonicalization.
* **Air-Gap SSRF & Proxy Hardening**: `is_loopback_endpoint()` and `preflight_isolation_check()` now reject CRLF/control characters, backslashes, URL fragments, percent-encoded authorities, IPv6-mapped IPv4 (`[::ffff:169.254.169.254]`, `[::ffff:7f00:1]`), non-canonical IPv6, octal/hex/decimal/shorthand IPv4 notations (`0177.0.0.1`, `2130706433`, `0x7f000001`, `127.1`), and DNS-rebinding tricks. `preflight_isolation_check()` now audits all `*_proxy` environment variables case-insensitively and fails closed by default (`strict_proxy = TRUE`) when outbound proxies lack explicit `127.0.0.1` and `localhost` entries in `NO_PROXY`.
* **Container & Symlink Injection Defense**: `airgap_container_spec()`, `emit_docker_run()`, `emit_docker_compose()`, and `emit_apptainer_def()` now block newline/shell/YAML/Apptainer `%post` injection, bind-mount `:` option injection, `..` traversal, dangerous linker/shell env vars (`LD_PRELOAD`, `BASH_ENV`), and security-override flags (`--privileged`, `--cap-add`, non-loopback `--host`), and POSIX-quote all Apptainer `%runscript` arguments. `verify_model_digest()` now rejects symbolic links by default (`allow_symlinks = FALSE`) and enforces canonical `root_dir` confinement.
* **Vault v2 Cryptography**: Upgraded `pii_vault_save()` and `pii_vault_load()` to `airgapllm_vault_v2` using RFC 5869 HKDF-SHA256 domain-separated keys with per-save random 128-bit salts, fresh random 128-bit IVs, full AAD header authentication, constant-time Encrypt-then-MAC verification strictly before decryption, and uniform error messages eliminating padding oracles (while retaining backward-compatible constant-time verification for v1 vaults).
* **HIPAA Safe Harbor, Unicode Defense & ReDoS Hardening**:
  - Added `hipaa_restricted_zip3()` and built-in `"age_over_89"` and `"zip_code"` HIPAA Safe Harbor entity detectors (covering ages > 89, 5-digit/ZIP+4 postal codes, and the 17 HHS restricted 3-digit ZIP prefixes).
  - Added index-preserving Unicode canonicalization defeating zero-width obfuscators (`U+200B`, `U+FEFF`, `U+00AD`), Unicode dashes, fullwidth ASCII, and Cyrillic/Greek homoglyphs.
  - Hardened all PII regular expressions with bounded quantifiers and linear IPv6 structural validation to prevent ReDoS catastrophic backtracking.
* **Prompt-Injection Framing, Output PII Scan & Resilient Checkpoints**:
  - Framed untrusted research text inside `<UNTRUSTED_RESEARCH_RECORD>` delimiters with tag-breakout neutralization and hardened local runtime system prompts.
  - Added post-inference output PII leakage scanning (`output_pii_action = c("redact", "error", "warn", "none")`) in `airgap_extract()`, recording integer `output_pii_leaks` counts in manifests and audit logs.
  - Hardened JSONL checkpoint and audit readers (`read_jsonl_raw_lines()`) against truncated UTF-8 and NUL byte corruption, scrubbed PII from persisted checkpoint error messages, and switched `audit_log_verify()` to constant-time digest checks.
* Added `SECURITY.md` documenting all v0.2.0 red-team findings and mitigations, plus `tests/testthat/test-adversarial-security.R`.

# airgapllm 0.1.0

* Initial CRAN-grade release providing the four core pillars: air-gapped Docker/Compose/Apptainer container lifecycle manager, pure-R pre-inference PII redaction & HMAC-SHA256 pseudonymization engine, crash-resumable schema-enforced batch extractor with local HTTP and deterministic mock runtimes, and tamper-evident SHA-256 hash-chained JSONL audit trail with IRB/HIPAA protocol narrative generator.
