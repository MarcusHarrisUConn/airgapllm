# Runnable Offline Example: Clinical & EMA Extraction with IRB Compliance Packet
# Execute via: source(system.file("examples/clinical_extraction_pipeline.R", package = "airgapllm"))

library(airgapllm)

# 1. Load bundled 100% synthetic clinical/EMA/educational notes dataset
data("synthetic_notes", package = "airgapllm")

# 2. Run a non-destructive pre-inference PII dry-run (zero raw PII emitted)
audit_dry <- pii_audit_dataframe(
  synthetic_notes,
  text_col = "note_text",
  id_col = "note_id",
  high_density_threshold = 3L
)
print(audit_dry)

# 3. Define a strictly typed extraction schema
schema <- extraction_schema(
  sentiment = schema_field("enum", values = c("positive", "neutral", "negative")),
  severity = schema_field("integer", min = 0L, max = 10L),
  crisis_flag = schema_field("logical"),
  summary = schema_field("character", max_length = 160L),
  name = "clinical_intake_v1"
)

# 4. Define a hardened, pinned local container specification
spec <- airgap_container_spec(
  backend = "ollama",
  image = "ollama/ollama",
  image_digest = paste0("sha256:", strrep("a", 64)),
  model_dir = "/srv/airgapllm/models",
  model_digest = paste0("sha256:", strrep("b", 64)),
  gpu = "nvidia"
)

# 5. Execute offline extraction with checkpointing & immutable audit logging
work_dir <- tempfile("airgap_example_")
dir.create(work_dir)
ck_path <- file.path(work_dir, "checkpoint.jsonl")
audit_path <- file.path(work_dir, "audit_log.jsonl")
pkt_dir <- file.path(work_dir, "irb_packet")

extracted <- airgap_extract(
  data = synthetic_notes[1:6, ],
  text_col = "note_text",
  schema = schema,
  runtime = runtime_mock(seed = 2026L),
  id_col = "note_id",
  pii_policy = "redact",
  checkpoint_path = ck_path,
  audit_log_path = audit_path,
  container_spec = spec
)

print(extracted)
print(audit_log_verify(audit_path))

# 6. Export self-contained, SHA-256-sealed IRB/HIPAA compliance packet
pkt <- export_irb_compliance_packet(
  out_dir = pkt_dir,
  extraction = extracted,
  audit_log_path = audit_path,
  container_spec = spec,
  study_title = "Offline Clinical Progress Note Extraction",
  protocol_id = "IRB-2026-0412",
  regulatory_framework = c("HIPAA", "IRB")
)
print(pkt)

# Clean up temporary working files
unlink(work_dir, recursive = TRUE)
