# Security Policy & v0.2.0 Red-Team Hardening Audit

`airgapllm` is designed for sensitive human-subjects research text
governed by **IRB, HIPAA, and FERPA** data-use agreements. This document
records the concrete vulnerabilities identified during the v0.2.0
adversarial red-team audit of v0.1.0, the architectural mitigations
implemented in `R/security.R` and across all four pillars, and guidance
for reporting security issues.

------------------------------------------------------------------------

## 1. v0.2.0 Adversarial Red-Team Findings & Mitigations

| \# | Severity | Surface | Vulnerability Identified in v0.1.0 | Remediation Implemented in v0.2.0 |
|:---|:---|:---|:---|:---|
| **F1** | **Critical** | Container & Apptainer Emitters (`R/container.R`) | `image`, `model_file`, `extra_args`, `env`, `model_dir`, `service_name`, and resource flags accepted newlines, shell metacharacters, `:` bind-mount options, or `%post` directives—enabling arbitrary shell/Apptainer/YAML injection or `:rw` mount downgrade. | Strict centralized validators in `R/security.R` (`assert_safe_container_image()`, `assert_safe_host_path()`, `assert_safe_model_file()`, `assert_safe_env_entry()`, `assert_safe_extra_args()`, `assert_safe_token()`). Rejects control chars/newlines, `:` in bind paths, `..` traversal, dangerous env vars (`LD_PRELOAD`, `BASH_ENV`), security-override flags (`--privileged`, `--cap-add`, `--network`, non-loopback `--host`), and POSIX-quotes all Apptainer `%runscript` arguments. |
| **F2** | **Critical** | Model Weight Integrity ([`verify_model_digest()`](https://marcusharrisphd.com/airgapllm/reference/verify_model_digest.md)) | Directory and file digest checks did not block symbolic links ([`Sys.readlink()`](https://rdrr.io/r/base/Sys.readlink.html)) or enforce canonical root confinement, allowing symlink escape (`model_dir/shard -> /etc/passwd`) or `../` traversal. | `assert_path_confined()` blocks `..` segments, rejects symbolic links by default (`allow_symlinks = FALSE`), walks intermediate path components inside `model_dir`, and verifies canonical [`normalizePath()`](https://rdrr.io/r/base/normalizePath.html) containment within `root_dir`. |
| **F3** | **High** | Air-Gap SSRF / URL Parser ([`is_loopback_endpoint()`](https://marcusharrisphd.com/airgapllm/reference/is_loopback_endpoint.md), [`preflight_isolation_check()`](https://marcusharrisphd.com/airgapllm/reference/preflight_isolation_check.md)) | [`trimws()`](https://rdrr.io/r/base/trimws.html) ran before whitespace validation (allowing trailing `\r\n` CRLF) and PCRE `$` matched before trailing `\n` (`unix:///var/run/llm.sock\n`); backslashes, `#` fragments, `%` authority encoding, and case-variant proxy variables (`Http_Proxy`, `SOCKS_PROXY`) were insufficiently constrained; active outbound proxies only issued an advisory warning instead of failing closed. | `classify_endpoint_strict()` validates raw byte range (`0x21..0x7e`, immune to PCRE `$` trailing-newline quirks) prior to parsing, rejects `\`, `#`, `@`, `%`, control chars/CRLF, IPv6-mapped IPv4 (`[::ffff:169.254.169.254]`, `[::ffff:7f00:1]`), non-canonical IPv6 (`[0:0:0:0:0:0:0:1]`), octal/hex/decimal/shorthand IPv4 notations (`0177.0.0.1`, `2130706433`, `0x7f000001`, `127.1`), trailing dots, and DNS-rebinding domains. `detect_outbound_proxies()` audits all `*_proxy` env vars case-insensitively and fails closed by default (`strict_proxy = TRUE`) unless `NO_PROXY` explicitly lists both `127.0.0.1` and `localhost`. |
| **F4** | **High** | Cryptographic Vault ([`pii_vault_save()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_save.md), [`pii_vault_load()`](https://marcusharrisphd.com/airgapllm/reference/pii_vault_load.md)) | Vault v1 used ad-hoc SHA-256 key derivation without per-save salt, lacked AAD binding over envelope metadata, and compared MAC hex strings via short-circuit [`identical()`](https://rdrr.io/r/base/identical.html) (timing side channel). | Vault v2 (`airgapllm_vault_v2`) implements RFC 5869 **HKDF-SHA256** (`hkdf_sha256()`) deriving completely separate pseudonymization, per-save AES-256-CBC encryption, and per-save HMAC-SHA256 keys from a fresh 128-bit random salt and fresh 128-bit random IV; authenticates full AAD (`format|cipher|vault_id|key_fingerprint|salt|iv|ct`); enforces **constant-time MAC verification (`constant_time_equal()`) strictly BEFORE decryption**; emits a uniform authentication error (defeating padding oracles); and enforces `0600` file permissions. |
| **F5** | **High** | PII Evasion, HIPAA Safe Harbor & Algorithmic DoS (`R/pii.R`) | Adversarial zero-width joiners/spaces (`U+200B`, `U+FEFF`, `U+00AD`), Unicode dashes (`U+2011`, `U+2212`), fullwidth ASCII, and Cyrillic/Greek homoglyphs bypassed regex detection; email lookahead `(?![A-Za-z0-9._%+-])` missed emails immediately followed by a sentence-ending period (`.`); HIPAA Safe Harbor rules for ages \> 89 and geographic ZIP codes (including the 17 HHS restricted 3-digit prefixes) were missing; O(M²) overlap resolution and O(N·M) span replacement plus unbounded regex quantifiers caused multi-second stalls on 50 KB dense inputs. | Index-preserving Unicode canonicalizer (`canonicalize_pii_text()`) maps homoglyphs/fullwidth/dashes and strips invisible obfuscators in O(n) while restoring exact original offsets; fixed email trailing lookahead to handle sentence-ending periods cleanly; added HIPAA Safe Harbor `age_over_89` and `zip_code` (with [`hipaa_restricted_zip3()`](https://marcusharrisphd.com/airgapllm/reference/hipaa_restricted_zip3.md)) to default entities; bounded all regex quantifiers, replaced multi-alternation IPv6 regex with linear structural validation, and rewrote `resolve_overlapping_spans()` to O(M log M) (`findInterval` + O(1) fast-path) and `apply_span_replacements()` to vectorized O(N + M) C-level slicing. |
| **F6** | **High** | Prompt Injection & Post-Inference Leakage (`R/extract.R`) | Raw text embedded directly into prompts without boundary delimiters or breakout escaping; model outputs were not scanned post-inference for echoed/memorized PII; raw enum values inside validation errors could be written into checkpoint `.error` fields. | Explicit `<UNTRUSTED_RESEARCH_RECORD>` data-boundary framing with tag-breakout neutralization (`neutralize_prompt_delimiters()`) and hardened runtime system prompts; added post-inference output PII leakage scanning (`output_pii_action = c("redact", "error", "warn", "none")`) tracking aggregate `output_pii_leaks` in manifests/audit logs; sanitized and PII-scrubbed checkpoint `.error` messages before writing to disk (`sanitize_checkpoint_error()`). |
| **F7** | **Medium** | Checkpoint & Audit Byte Integrity (`R/extract.R`, `R/audit.R`) | [`readLines()`](https://rdrr.io/r/base/readLines.html) on raw files could fail unpredictably on truncated multi-byte UTF-8 or embedded NUL bytes; audit hash equality used non-constant-time [`identical()`](https://rdrr.io/r/base/identical.html). | Raw byte-level JSONL reader (`read_jsonl_raw_lines()`) detects NUL bytes and invalid UTF-8 deterministically: checkpoints gracefully recover truncated trailing UTF-8/JSON crash writes while failing closed on mid-file corruption; [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md) uses `constant_time_equal()` and flags any NUL/UTF-8 corruption as tampered. |

------------------------------------------------------------------------

## 2. Cryptographic Architecture Summary

- **Key Derivation:** RFC 5869 `HKDF-SHA256` with domain-separated
  `info` strings:
  - Pseudonymization HMAC key: `salt = "airgapllm-v2-pseudonym-salt"`,
    `info = "airgapllm:pseudonym:hmac-sha256"`.
  - Per-save Vault Encryption key: fresh 128-bit random `salt_b64`,
    `info = "airgapllm:vault:aes-256-cbc:v2"`.
  - Per-save Vault Authentication key: fresh 128-bit random `salt_b64`,
    `info = "airgapllm:vault:hmac-sha256:v2"`.
- **Authenticated Encryption (Vault v2):** Encrypt-then-MAC
  (`AES-256-CBC` with fresh 128-bit IV + `HMAC-SHA256` over
  `AAD || salt || iv || ciphertext`), verified in constant time before
  decryption.
- **Audit Trail Chain:** Canonical key-sorted JSON serialized in UTF-8,
  chained from `"GENESIS"` via `SHA-256`, verified in constant time
  across sequence continuity, chain links, and strict zero-PII schema
  allowlists.
- **File Permissions:** Vault files are written atomically
  (`tmp -> chmod 0600 -> rename -> chmod 0600`).

------------------------------------------------------------------------

## 3. Responsible Security Reporting

If you discover a security vulnerability, air-gap bypass, PII leakage
vector, or cryptographic weakness in `airgapllm`, please report it
privately to the maintainer (`marcus.harris.uconn@gmail.com`) or open an
advisory at `https://github.com/MarcusHarrisUConn/airgapllm/security`
rather than posting sensitive clinical examples publicly.
