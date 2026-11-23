# Runnable Offline Example: HPC GPU Sizing, Apptainer Config & Long-Transcript Chunking
# Execute via: source(system.file("examples/hpc_apptainer_workflow.R", package = "airgapllm"))

library(airgapllm)

# 1. Estimate GPU VRAM requirements across quantizations before requesting Slurm GPUs
vram_8b <- estimate_vram_requirements(8, quantization = "Q4_K_M", context_length = 8192L, batch_size = 2L)
print(vram_8b)

vram_70b <- estimate_vram_requirements(70, quantization = "Q4_K_M", context_length = 4096L, batch_size = 1L)
print(vram_70b)

# 2. Generate hardened, digest-pinned HPC Apptainer .def & Docker Compose specs
work_dir <- tempfile("airgap_hpc_")
dir.create(work_dir)
model_stub <- file.path(work_dir, "llama-3.1-8b-instruct-q4_K_M.gguf")
writeBin(charToRaw("synthetic-gguf-header-for-digest-demo"), model_stub)
model_ver <- verify_model_digest(model_stub)

spec <- airgap_container_spec(
  backend = "llama.cpp",
  image = "ghcr.io/ggerganov/llama.cpp",
  image_digest = paste0("sha256:", strrep("c", 64)),
  model_dir = work_dir,
  model_file = basename(model_stub),
  model_digest = model_ver$actual_digest,
  gpu = "nvidia",
  memory_limit = "24g",
  user = "1000:1000"
)

def_path <- file.path(work_dir, "airgap_llama.def")
emit_apptainer_def(spec, file = def_path)
pf <- preflight_isolation_check(spec = spec, endpoint = "http://127.0.0.1:8080/v1", model_path = model_stub)
print(pf)

# 3. Chunk a long multi-paragraph synthetic transcript before batch extraction
data("synthetic_notes", package = "airgapllm")
long_doc <- synthetic_notes[synthetic_notes$note_id == "SYN_016", ]
chunks <- chunk_clinical_texts(
  long_doc,
  text_col = "note_text",
  id_col = "note_id",
  max_chars = 350L,
  overlap_chars = 60L,
  split_on = "paragraph"
)
print(chunks[, c("doc_id", "chunk_id", "chunk_index", "n_chunks", "char_count")])

# Clean up temporary working files
unlink(work_dir, recursive = TRUE)
