#' Synthetic Clinical, EMA, and Educational Research Notes Dataset
#'
#' A 100 percent fictional teaching dataset containing realistic synthetic
#' therapy session notes, ecological momentary assessment (EMA) journal entries,
#' and educational student reflections engineered specifically for offline
#' demonstrations, unit tests, and tutorials in `airgapllm`. All names, emails
#' (`@example.org`), phone numbers (`555-01xx` NANP reserved range), street
#' addresses, medical record numbers, social security numbers, ages over 89,
#' and geographic ZIP codes are completely fabricated and correspond to no real
#' individuals.
#'
#' @format A `tibble` with 16 rows and 6 columns:
#' \describe{
#'   \item{note_id}{Character unique note identifier (`"SYN_001"` to `"SYN_016"`).}
#'   \item{domain}{Character research domain (`"clinical_therapy"`,
#'     `"ema_journal"`, or `"student_writing"`).}
#'   \item{site}{Character fictional study site label (`"Site_North"`,
#'     `"Site_South"`, or `"Site_West"`).}
#'   \item{wave}{Integer longitudinal assessment wave (`1L` or `2L`).}
#'   \item{contains_synthetic_phi}{Logical indicator of whether the row
#'     intentionally embeds fictional PII/PHI patterns.}
#'   \item{note_text}{Character unstructured text body (including one
#'     multi-paragraph transcript for demonstrating [chunk_clinical_texts()]
#'     and HIPAA Safe Harbor edge cases such as ages > 89 and restricted
#'     3-digit ZIP prefixes).}
#' }
#'
#' @source 100 percent synthetically constructed for `airgapllm` documentation
#'   and reproducible offline verification.
#'
#' @examples
#' data("synthetic_notes", package = "airgapllm")
#' nrow(synthetic_notes)
#' pii_privacy_report(synthetic_notes, text_col = "note_text")
"synthetic_notes"
