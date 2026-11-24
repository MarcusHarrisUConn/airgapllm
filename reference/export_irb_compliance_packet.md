# Export a Self-Contained, Strictly PII-Free IRB / HIPAA Compliance Packet

Assembles a self-contained audit directory suitable for attachment to an
IRB protocol submission, HIPAA Security Officer review, or reproducible
publication supplement. The packet includes a verified hash-chained
JSONL audit log, pre-flight isolation attestation JSON, hardened
container configurations (`docker run`, Compose YAML, Apptainer `.def`)
when a pinned `container_spec` is supplied, ready-to-paste Markdown and
Quarto IRB narratives, and a SHA-256 `packet_manifest.json`. Every file
written to the packet is scanned for accidental raw PII before sealing.

## Usage

``` r
export_irb_compliance_packet(
  out_dir,
  extraction = NULL,
  audit_log_path = NULL,
  container_spec = NULL,
  preflight = NULL,
  study_title = NULL,
  protocol_id = NULL,
  institution = NULL,
  pi_name = NULL,
  regulatory_framework = c("HIPAA", "IRB"),
  overwrite = FALSE
)
```

## Arguments

- out_dir:

  Character scalar destination directory path for the compliance packet.

- extraction:

  Optional `airgap_extraction` or `airgap_consensus` result from
  [`airgap_extract()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract.md)
  or
  [`airgap_extract_consensus()`](https://marcusharrisphd.com/airgapllm/reference/airgap_extract_consensus.md).

- audit_log_path:

  Optional path to an existing hash-chained JSONL audit log (verified
  via
  [`audit_log_verify()`](https://marcusharrisphd.com/airgapllm/reference/audit_log_verify.md)
  prior to inclusion).

- container_spec:

  Optional
  [`airgap_container_spec()`](https://marcusharrisphd.com/airgapllm/reference/airgap_container_spec.md)
  object. If pinned with `image_digest`, emits
  `container_docker_run.sh`, `docker-compose.yml`, and
  `container_apptainer.def` into the packet.

- preflight:

  Optional `airgap_preflight` record (defaults to
  `extraction_preflight(extraction)` when `extraction` is provided).

- study_title:

  Optional character scalar study title.

- protocol_id:

  Optional character scalar IRB protocol ID.

- institution:

  Optional character scalar institutional name.

- pi_name:

  Optional character scalar Principal Investigator name (for protocol
  header; omitted when `NULL`).

- regulatory_framework:

  Character vector subset of `c("HIPAA", "IRB", "FERPA")`.

- overwrite:

  Logical scalar; if `FALSE` (default), refuses to overwrite a non-empty
  `out_dir`.

## Value

An S3 object of class `"airgap_compliance_packet"` containing `out_dir`,
`files` (tibble of relative paths, sizes, and SHA-256 digests),
`packet_digest`, `audit_valid`, `audit_chain_head`, and `created_at`.

## Examples

``` r
df <- tibble::tibble(id = c("N1", "N2"), txt = c("Dr. Jane Doe visited.", "Mood stable."))
sc <- extraction_schema(mood = schema_field("enum", values = c("calm", "anxious")))
res <- airgap_extract(df, "txt", sc, runtime_mock(), id_col = "id")
pkt_dir <- file.path(tempdir(), "demo_irb_packet")
pkt <- export_irb_compliance_packet(
  pkt_dir,
  extraction = res,
  protocol_id = "IRB-2026-0412",
  overwrite = TRUE
)
pkt
#> <airgap_compliance_packet> [AUDIT: VERIFIED]
#>   Directory:     /tmp/RtmpYwr7Bt/demo_irb_packet
#>   Artifacts:     4 file(s) + packet_manifest.json
#>   Audit head:    sha256:3411d24d72302e5d7852c8bfbfd277c0920a43145f9b4e24f16d8f8b8ba84e03
#>   Packet digest: sha256:59b0341356a3917df7abfb8e4256aa8fecd1d8a81e505a556cd40ca2fa36e8f0
unlink(pkt_dir, recursive = TRUE)
```
