# Pillar 2: Pre-Inference Privacy & PII Engine (Pure R)

#' Default Built-In PII Entity Types
#'
#' Returns the default ordered vector of built-in PII entity types supported by
#' [pii_config()], [pii_detect()], [pii_redact()], and [pii_pseudonymize()].
#'
#' @return A character vector of built-in entity type identifiers.
#'
#' @export
#' @examples
#' pii_default_entities()
pii_default_entities <- function() {
  c(
    "email",
    "ssn",
    "street_address",
    "mrn_id",
    "ip_address",
    "phone",
    "date",
    "person_name"
  )
}

#' Non-name stopword dictionary to reduce false positives in unlabeled name heuristic
#' @noRd
pii_name_stopwords <- function() {
  c(
    "a", "an", "the", "this", "that", "these", "those", "my", "our", "your",
    "his", "her", "their", "its", "some", "any", "each", "every", "many",
    "much", "most", "several", "other", "another", "both", "all", "no", "none",
    "when", "where", "while", "after", "before", "during", "since", "until",
    "because", "although", "though", "however", "therefore", "moreover",
    "furthermore", "meanwhile", "otherwise", "instead", "today", "yesterday",
    "tomorrow", "tonight", "here", "there", "now", "then", "also", "still",
    "only", "just", "very", "quite", "rather", "almost", "already", "always",
    "never", "often", "sometimes", "usually", "frequently", "rarely",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "jan", "feb", "mar", "apr",
    "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec",
    "spring", "summer", "fall", "autumn", "winter", "morning", "afternoon",
    "evening", "night", "week", "month", "year", "day",
    "patient", "client", "student", "participant", "subject", "clinician",
    "therapist", "physician", "doctor", "nurse", "counselor", "teacher",
    "parent", "guardian", "mother", "father", "sibling", "family", "child",
    "clinical", "medical", "mental", "behavioral", "physical", "social",
    "primary", "secondary", "acute", "chronic", "severe", "moderate", "mild",
    "major", "minor", "generalized", "bipolar", "depressive", "depression",
    "anxiety", "panic", "trauma", "stress", "posttraumatic", "cognitive",
    "dialectical", "interpersonal", "psychodynamic", "motivational", "therapy",
    "counseling", "treatment", "intervention", "medication", "prescription",
    "diagnosis", "disorder", "syndrome", "disease", "condition", "symptom",
    "symptoms", "history", "intake", "discharge", "assessment", "evaluation",
    "screening", "inventory", "scale", "index", "questionnaire", "survey",
    "test", "score", "scores", "grade", "grades", "report", "note", "notes",
    "summary", "plan", "progress", "session", "visit", "follow", "followup",
    "appointment", "referral", "consultation", "review", "record", "records",
    "chart", "file", "study", "protocol", "trial", "cohort", "group", "control",
    "hospital", "clinic", "center", "centre", "institute", "institution",
    "university", "college", "school", "academy", "high", "middle", "elementary",
    "department", "division", "unit", "ward", "emergency", "room", "office",
    "health", "care", "healthcare", "services", "system", "program", "project",
    "united", "states", "america", "american", "national", "federal", "state",
    "county", "city", "town", "village", "district", "north", "south", "east",
    "west", "central", "new", "old", "upper", "lower", "great", "grand",
    "street", "avenue", "road", "boulevard", "drive", "lane", "court", "place",
    "circle", "terrace", "parkway", "highway", "trail", "way", "box",
    "security", "number", "date", "birth", "email", "phone", "address",
    "english", "spanish", "french", "german", "chinese", "math", "mathematics",
    "science", "biology", "chemistry", "physics", "psychology", "sociology",
    "economics", "education", "reading", "writing", "literature", "statistics",
    "overall", "general", "initial", "final", "recent", "current", "previous",
    "prior", "next", "first", "second", "third", "last", "total", "average",
    "positive", "negative", "neutral", "normal", "abnormal", "elevated", "low",
    "sleep", "mood", "affect", "speech", "thought", "insight", "judgment",
    "orientation", "memory", "attention", "concentration", "appetite", "energy",
    "suicidal", "homicidal", "ideation", "safety", "crisis", "risk", "protective",
    "factors", "coping", "skills", "goals", "homework", "exercise", "journal"
  )
}

#' Configure Pre-Inference PII Detection and Redaction Rules
#'
#' Builds a validated PII detection configuration controlling which built-in
#' entity classes are active, plus lab-supplied custom regex patterns, custom
#' literal dictionaries (e.g., local clinic names, participant lists), and
#' allowlisted terms that must not be flagged.
#'
#' @param entities Character vector of built-in entity types to detect. See
#'   [pii_default_entities()].
#' @param custom_patterns Optional named character vector of PCRE regular
#'   expressions, where names specify the entity type label (e.g.,
#'   `c(study_code = "STUDY-[0-9]{5}")`).
#' @param custom_dictionary Optional named list of character vectors containing
#'   literal sensitive terms grouped by entity type (e.g.,
#'   `list(clinic_name = c("Hartford General"), person_name = c("Maya Lin"))`).
#' @param allowlist Optional character vector of literal terms or phrases that
#'   must never be flagged as PII (case-insensitive exact match).
#' @param detect_unlabeled_names Logical scalar; if `TRUE` (default), enables
#'   capitalization-based detection of multi-word person names (filtered against
#'   common clinical/academic stopwords) in addition to titled (`Dr. ...`) and
#'   role-labeled (`Patient: ...`) names.
#' @param case_sensitive_dictionary Logical scalar; whether `custom_dictionary`
#'   matching is case-sensitive. Defaults to `FALSE`.
#'
#' @return An S3 object of class `"airgap_pii_config"` with canonical
#'   `config_digest`.
#'
#' @export
#' @examples
#' cfg <- pii_config(
#'   custom_patterns = c(study_id = "UCONN-[0-9]{4}"),
#'   custom_dictionary = list(clinic = c("Valley Behavioral Clinic")),
#'   allowlist = c("Beck Depression Inventory")
#' )
#' print(cfg)
pii_config <- function(
  entities = pii_default_entities(),
  custom_patterns = NULL,
  custom_dictionary = NULL,
  allowlist = NULL,
  detect_unlabeled_names = TRUE,
  case_sensitive_dictionary = FALSE
) {
  valid_entities <- pii_default_entities()
  if (!is.character(entities)) {
    cli::cli_abort("{.arg entities} must be a character vector.", class = "airgap_validation_error")
  }
  bad_ent <- setdiff(entities, valid_entities)
  if (length(bad_ent) > 0L) {
    cli::cli_abort(
      "Unknown PII entity type(s): {paste(bad_ent, collapse = ', ')}. Valid types: {paste(valid_entities, collapse = ', ')}.",
      class = "airgap_validation_error"
    )
  }
  entities <- unique(entities)

  if (!is.null(custom_patterns)) {
    if (!is.character(custom_patterns) || is.null(names(custom_patterns)) || any(!nzchar(names(custom_patterns)))) {
      cli::cli_abort("{.arg custom_patterns} must be a named character vector of regexes.", class = "airgap_validation_error")
    }
    for (nm in names(custom_patterns)) {
      pat <- custom_patterns[[nm]]
      if (is.na(pat) || !nzchar(pat)) {
        cli::cli_abort("Custom pattern {.val {nm}} must be a non-empty string.", class = "airgap_validation_error")
      }
      tryCatch(
        grepl(pat, "", perl = TRUE),
        error = function(e) {
          cli::cli_abort(
            c("Invalid PCRE regular expression in `custom_patterns[['{nm}']]`.", "x" = conditionMessage(e)),
            class = "airgap_validation_error"
          )
        }
      )
    }
  }

  if (!is.null(custom_dictionary)) {
    if (!is.list(custom_dictionary) || is.null(names(custom_dictionary)) || any(!nzchar(names(custom_dictionary)))) {
      cli::cli_abort("{.arg custom_dictionary} must be a named list of character vectors.", class = "airgap_validation_error")
    }
    for (nm in names(custom_dictionary)) {
      vals <- custom_dictionary[[nm]]
      if (!is.character(vals)) {
        cli::cli_abort("Entry {.val {nm}} in {.arg custom_dictionary} must be a character vector.", class = "airgap_validation_error")
      }
      custom_dictionary[[nm]] <- unique(vals[!is.na(vals) & nzchar(trimws(vals))])
    }
  }

  if (!is.null(allowlist)) {
    if (!is.character(allowlist)) {
      cli::cli_abort("{.arg allowlist} must be a character vector.", class = "airgap_validation_error")
    }
    allowlist <- unique(allowlist[!is.na(allowlist) & nzchar(trimws(allowlist))])
  }

  assert_scalar_logical(detect_unlabeled_names, "detect_unlabeled_names")
  assert_scalar_logical(case_sensitive_dictionary, "case_sensitive_dictionary")

  # Config digest deliberately hashes structure & entity metadata (and hashes of custom terms, never storing raw dictionary text in logs)
  digest_payload <- list(
    entities = sort(entities),
    custom_pattern_names = if (is.null(custom_patterns)) list() else sort(names(custom_patterns)),
    custom_pattern_hashes = if (is.null(custom_patterns)) list() else as.list(vapply(custom_patterns, sha256_string, character(1L))),
    custom_dictionary_counts = if (is.null(custom_dictionary)) list() else lapply(custom_dictionary, length),
    allowlist_count = length(allowlist),
    detect_unlabeled_names = detect_unlabeled_names,
    case_sensitive_dictionary = case_sensitive_dictionary
  )

  structure(
    list(
      entities = entities,
      custom_patterns = custom_patterns,
      custom_dictionary = custom_dictionary,
      allowlist = allowlist,
      detect_unlabeled_names = detect_unlabeled_names,
      case_sensitive_dictionary = case_sensitive_dictionary,
      config_digest = sha256_object(digest_payload)
    ),
    class = "airgap_pii_config"
  )
}

#' @export
print.airgap_pii_config <- function(x, ...) {
  cat("<airgap_pii_config>\n")
  cat("  Entities:          ", paste(x$entities, collapse = ", "), "\n", sep = "")
  cat("  Custom patterns:   ", length(x$custom_patterns), "\n", sep = "")
  dict_n <- if (is.null(x$custom_dictionary)) 0L else sum(vapply(x$custom_dictionary, length, integer(1L)))
  cat("  Dictionary terms:  ", dict_n, "\n", sep = "")
  cat("  Allowlist terms:   ", length(x$allowlist), "\n", sep = "")
  cat("  Unlabeled names:   ", x$detect_unlabeled_names, "\n", sep = "")
  cat("  Config digest:     ", x$config_digest, "\n", sep = "")
  invisible(x)
}

#' Escape regex metacharacters for literal dictionary matching
#' @noRd
escape_regex <- function(x) {
  gsub("([.\\^$|()*+?{}\\[\\]\\\\])", "\\\\\\1", x, perl = TRUE)
}

#' Run a single PCRE pattern on one string and return span list
#' @noRd
match_spans_regex <- function(text, pattern, entity_type, priority, capture_group = 0L, filter_fn = NULL) {
  if (!nzchar(text)) return(list())
  m <- gregexpr(pattern, text, perl = TRUE)[[1L]]
  if (length(m) == 1L && m[1L] == -1L) return(list())

  if (capture_group > 0L) {
    cs <- attr(m, "capture.start")
    cl <- attr(m, "capture.length")
    if (is.null(cs) || ncol(cs) < capture_group) return(list())
    starts <- as.integer(cs[, capture_group])
    lens <- as.integer(cl[, capture_group])
  } else {
    starts <- as.integer(m)
    lens <- as.integer(attr(m, "match.length"))
  }

  out <- vector("list", length(starts))
  k <- 0L
  for (i in seq_along(starts)) {
    st <- starts[i]
    ln <- lens[i]
    if (is.na(st) || st < 1L || is.na(ln) || ln < 1L) next
    en <- st + ln - 1L
    val <- substr(text, st, en)
    if (!is.null(filter_fn) && !isTRUE(filter_fn(val, text, st, en))) next
    k <- k + 1L
    out[[k]] <- list(
      entity_type = entity_type,
      start = st,
      end = en,
      length = ln,
      match = val,
      priority = priority
    )
  }
  if (k == 0L) list() else out[seq_len(k)]
}

#' Resolve overlapping PII spans deterministically by priority, length, and position
#' @noRd
resolve_overlapping_spans <- function(spans) {
  if (length(spans) <= 1L) return(spans)

  pri <- vapply(spans, `[[`, integer(1L), "priority")
  len <- vapply(spans, `[[`, integer(1L), "length")
  st <- vapply(spans, `[[`, integer(1L), "start")

  # Lower priority integer = higher precedence; longer span wins ties; earlier start wins ties
  ord <- order(pri, -len, st)
  spans <- spans[ord]

  kept <- list()
  for (sp in spans) {
    overlaps <- FALSE
    for (k in kept) {
      if (sp$start <= k$end && sp$end >= k$start) {
        overlaps <- TRUE
        break
      }
    }
    if (!overlaps) {
      kept[[length(kept) + 1L]] <- sp
    }
  }

  # Sort final non-overlapping spans by ascending start offset
  kept_st <- vapply(kept, `[[`, integer(1L), "start")
  kept[order(kept_st)]
}

#' Detect PII spans within a single character string
#' @noRd
detect_pii_single <- function(text, config, stopwords) {
  if (is.na(text) || !nzchar(text)) return(list())

  spans <- list()
  add_spans <- function(x) {
    if (length(x) > 0L) spans <<- c(spans, x)
  }

  # Priority 1: Custom regex patterns
  if (!is.null(config$custom_patterns) && length(config$custom_patterns) > 0L) {
    for (nm in names(config$custom_patterns)) {
      add_spans(match_spans_regex(text, config$custom_patterns[[nm]], nm, priority = 10L))
    }
  }

  # Priority 2: Custom literal dictionaries
  if (!is.null(config$custom_dictionary) && length(config$custom_dictionary) > 0L) {
    for (nm in names(config$custom_dictionary)) {
      terms <- config$custom_dictionary[[nm]]
      if (length(terms) == 0L) next
      # Sort longest first so multi-word dictionary phrases win
      terms <- terms[order(-nchar(terms))]
      esc <- vapply(terms, escape_regex, character(1L))
      prefix <- if (isTRUE(config$case_sensitive_dictionary)) "" else "(?i)"
      pat <- paste0(prefix, "(?<![A-Za-z0-9_])(?:", paste(esc, collapse = "|"), ")(?![A-Za-z0-9_])")
      add_spans(match_spans_regex(text, pat, nm, priority = 15L))
    }
  }

  ents <- config$entities

  # Priority 20: Email
  if ("email" %in% ents) {
    add_spans(match_spans_regex(
      text,
      "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}(?![A-Za-z0-9._%+-])",
      "email",
      priority = 20L
    ))
  }

  # Priority 25: SSN
  if ("ssn" %in% ents) {
    add_spans(match_spans_regex(
      text,
      "(?i)\\b(?:SSN|Social\\s+Security(?:\\s+(?:No\\.?|Number|#))?)\\s*[:#-]?\\s*((?!000|666|9\\d{2})\\d{3}[- ]?(?!00)\\d{2}[- ]?(?!0000)\\d{4})\\b",
      "ssn",
      priority = 24L,
      capture_group = 1L
    ))
    add_spans(match_spans_regex(
      text,
      "(?<!\\d)(?!000|666|9\\d{2})\\d{3}[- ](?!00)\\d{2}[- ](?!0000)\\d{4}(?!\\d)",
      "ssn",
      priority = 25L
    ))
  }

  # Priority 30: Street addresses & PO Boxes (higher than person_name so "Dr." street isn't misparsed as Doctor)
  if ("street_address" %in% ents) {
    street_pat <- paste0(
      "\\b\\d{1,6}\\s+(?:[NSEW]\\.?\\s+)?(?:[A-Za-z0-9.'-]+\\s+){1,4}",
      "(?i:Street|St\\.?|Avenue|Ave\\.?|Road|Rd\\.?|Boulevard|Blvd\\.?|Drive|Dr\\.?|",
      "Lane|Ln\\.?|Court|Ct\\.?|Way|Place|Pl\\.?|Circle|Cir\\.?|Terrace|Ter\\.?|",
      "Parkway|Pkwy\\.?|Highway|Hwy\\.?|Trail|Trl\\.?)",
      "(?:(?:\\s*,\\s*|\\s+)(?i:Apt\\.?|Apartment|Suite|Ste\\.?|Unit|#)\\s*[A-Za-z0-9-]+)?",
      "(?:\\s*,\\s*[A-Z][a-zA-Z. ]+,\\s*[A-Z]{2}\\s+\\d{5}(?:-\\d{4})?)?",
      "(?![A-Za-z0-9])"
    )
    add_spans(match_spans_regex(text, street_pat, "street_address", priority = 30L))
    add_spans(match_spans_regex(text, "(?i)\\bP\\.?\\s*O\\.?\\s*Box\\s+\\d+\\b", "street_address", priority = 30L))
  }

  # Priority 35: MRN / Patient / Student IDs
  if ("mrn_id" %in% ents) {
    mrn_labeled <- paste0(
      "(?i)\\b(?:MRN|Med(?:ical)?\\s*Rec(?:ord)?(?:\\s*(?:No\\.?|Number|#))?|",
      "Patient\\s*ID|Pt\\.?\\s*ID|Subject\\s*ID|Participant\\s*ID|",
      "Student\\s*ID|SID|UID|Chart\\s*(?:No\\.?|#))",
      "\\s*[:#-]?\\s*[A-Za-z0-9][A-Za-z0-9-]{2,19}\\b"
    )
    add_spans(match_spans_regex(text, mrn_labeled, "mrn_id", priority = 34L))
    add_spans(match_spans_regex(text, "\\b(?:MRN|PID|SID|STU|PAT)[-_]?\\d{4,12}\\b", "mrn_id", priority = 35L))
  }

  # Priority 40: IP addresses (IPv4 & IPv6)
  if ("ip_address" %in% ents) {
    ipv4_pat <- "(?<![\\d.])(?:(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)(?![\\d.])"
    add_spans(match_spans_regex(text, ipv4_pat, "ip_address", priority = 40L))

    ipv6_pat <- paste0(
      "(?i)(?<![0-9a-f:])(?:",
      "(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|",
      "(?:[0-9a-f]{1,4}:){1,7}:|",
      ":(?::[0-9a-f]{1,4}){1,7}|",
      "(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|",
      "(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|",
      "(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|",
      "(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|",
      "(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|",
      "[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}",
      ")(?![0-9a-f:])"
    )
    add_spans(match_spans_regex(
      text,
      ipv6_pat,
      "ip_address",
      priority = 40L,
      filter_fn = function(val, ...) grepl(":", val, fixed = TRUE) && grepl("[0-9a-fA-F]", val)
    ))
  }

  # Priority 45: Phone numbers (US and international)
  if ("phone" %in% ents) {
    us_phone <- paste0(
      "(?<!\\d)(?:",
      "\\+1[-.\\s]?(?:\\([2-9]\\d{2}\\)|[2-9]\\d{2})[-.\\s]?\\d{3}[-.\\s]?\\d{4}|",
      "1[-.\\s]\\([2-9]\\d{2}\\)[-.\\s]?\\d{3}[-.\\s]?\\d{4}|",
      "1[-.\\s][2-9]\\d{2}[-.\\s]\\d{3}[-.\\s]\\d{4}|",
      "\\([2-9]\\d{2}\\)[-.\\s]?\\d{3}[-.\\s]?\\d{4}|",
      "[2-9]\\d{2}[-.\\s]\\d{3}[-.\\s]\\d{4}",
      ")(?:\\s*(?i:ext\\.?|x)\\s*\\d{1,5})?(?!\\d)"
    )
    add_spans(match_spans_regex(text, us_phone, "phone", priority = 45L))

    intl_phone <- "(?<!\\d)\\+[1-9]\\d{0,2}(?:[-.\\s]?\\(?\\d{1,4}\\)?){2,5}(?:\\s*(?i:ext\\.?|x)\\s*\\d{1,5})?(?!\\d)"
    add_spans(match_spans_regex(
      text,
      intl_phone,
      "phone",
      priority = 46L,
      filter_fn = function(val, ...) {
        main_part <- sub("\\s*(?i:ext\\.?|x).*$", "", val, perl = TRUE)
        digits <- gsub("[^0-9]", "", main_part)
        nchar(digits) >= 7L && nchar(digits) <= 15L
      }
    ))
  }

  # Priority 50: Dates & DOBs
  if ("date" %in% ents) {
    month_pat <- "(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
    dob_pat <- paste0(
      "(?i)\\b(?:DOB|D\\.O\\.B\\.|Date\\s+of\\s+Birth|Birthdate)\\s*[:#-]?\\s*(?:",
      "(?:19|20)\\d{2}[-/.]\\d{1,2}[-/.]\\d{1,2}|",
      "\\d{1,2}[-/.]\\d{1,2}[-/.](?:19|20)?\\d{2}|",
      month_pat, "\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+(?:19|20)\\d{2}",
      ")\\b"
    )
    add_spans(match_spans_regex(text, dob_pat, "date", priority = 49L))
    add_spans(match_spans_regex(
      text,
      "(?<!\\d)(?:19|20)\\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\\d|3[01])(?!\\d)",
      "date",
      priority = 50L
    ))
    add_spans(match_spans_regex(
      text,
      "(?<!\\d)(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\\d|3[01])[/-](?:(?:19|20)\\d{2}|\\d{2})(?!\\d)",
      "date",
      priority = 50L
    ))
    add_spans(match_spans_regex(
      text,
      "(?<!\\d)(?:1[3-9]|2\\d|3[01])[/-](?:0?[1-9]|1[0-2])[/-](?:(?:19|20)\\d{2}|\\d{2})(?!\\d)",
      "date",
      priority = 50L
    ))
    add_spans(match_spans_regex(
      text,
      paste0("(?i)\\b", month_pat, "\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+(?:19|20)\\d{2}\\b"),
      "date",
      priority = 50L
    ))
    add_spans(match_spans_regex(
      text,
      paste0("(?i)\\b\\d{1,2}(?:st|nd|rd|th)?\\s+", month_pat, "\\.?,?\\s+(?:19|20)\\d{2}\\b"),
      "date",
      priority = 50L
    ))
  }

  # Priority 60: Person names (titled, role-labeled, and optional unlabeled heuristic)
  if ("person_name" %in% ents) {
    # 1. Titled names (Dr., Mr., Mrs., Ms., Prof., etc.)
    titled_pat <- "\\b(?:Dr|Mr|Mrs|Ms|Miss|Mx|Prof|Professor|Rev|Hon)\\.?\\s+[A-Z][a-zA-Z'-]+(?:\\s+[A-Z]\\.)?(?:\\s+[A-Z][a-zA-Z'-]+){0,2}\\b"
    add_spans(match_spans_regex(
      text,
      titled_pat,
      "person_name",
      priority = 58L,
      filter_fn = function(val, ...) {
        # Ensure at least the first name token after title isn't a stopword
        toks <- strsplit(trimws(val), "\\s+")[[1L]]
        if (length(toks) < 2L) return(FALSE)
        name_toks <- tolower(gsub("[^A-Za-z]", "", toks[-1L]))
        !all(name_toks %in% stopwords)
      }
    ))

    # 2. Role-cued names ("Patient: Jane Doe", "Student: Marcus Harris")
    role_pat <- "\\b(?:Patient|Client|Student|Participant|Subject|Clinician|Therapist|Physician|Doctor|Parent|Guardian|Name)\\s*:\\s*([A-Z][a-zA-Z'-]+(?:\\s+[A-Z]\\.)?(?:\\s+[A-Z][a-zA-Z'-]+){0,2})\\b"
    add_spans(match_spans_regex(
      text,
      role_pat,
      "person_name",
      priority = 59L,
      capture_group = 1L,
      filter_fn = function(val, ...) {
        toks <- tolower(gsub("[^A-Za-z]", "", strsplit(trimws(val), "\\s+")[[1L]]))
        !all(toks %in% stopwords)
      }
    ))

    # 3. Unlabeled two-word / middle-initial capitalized names (filtered via stopwords)
    if (isTRUE(config$detect_unlabeled_names)) {
      unlabeled_pat <- paste0(
        "\\b[A-Z][a-z]{1,20}(?:-[A-Z][a-z]{1,20})?",
        "(?:\\s+[A-Z]\\.)?",
        "\\s+[A-Z](?:[a-z]{1,20}|'[A-Z][a-z]{1,20}|c[A-Z][a-z]{1,20})(?:-[A-Z][a-z]{1,20})?\\b"
      )
      add_spans(match_spans_regex(
        text,
        unlabeled_pat,
        "person_name",
        priority = 62L,
        filter_fn = function(val, ...) {
          toks <- strsplit(trimws(val), "\\s+")[[1L]]
          # Strip middle initial like "A."
          non_init <- toks[!grepl("^[A-Z]\\.$", toks)]
          if (length(non_init) < 2L) return(FALSE)
          clean_toks <- tolower(gsub("[^A-Za-z]", "", non_init))
          !any(clean_toks %in% stopwords)
        }
      ))
    }
  }

  # Apply allowlist filtering (case-insensitive exact match)
  if (!is.null(config$allowlist) && length(config$allowlist) > 0L && length(spans) > 0L) {
    allow_lc <- tolower(trimws(config$allowlist))
    spans <- Filter(function(sp) !(tolower(trimws(sp$match)) %in% allow_lc), spans)
  }

  resolve_overlapping_spans(spans)
}

#' Detect PII Entities in Character Text
#'
#' Runs deterministic pure-R PII detection over a character vector covering
#' emails, SSNs, US/international phone numbers, dates/DOBs, MRNs/student IDs,
#' IPv4/IPv6 addresses, street addresses, person names, and user-supplied custom
#' regex patterns and dictionaries.
#'
#' @param text Character vector of documents to scan.
#' @param config An [pii_config()] configuration object.
#' @param include_values Logical scalar; if `TRUE` (default), includes the
#'   matched `match` text column for local inspection; if `FALSE`, replaces the
#'   column with `"[MASKED]"` while retaining exact offsets and `value_hash`.
#'
#' @return A `tibble` with columns `doc_id`, `entity_type`, `start`, `end`,
#'   `length`, `match`, and `value_hash`.
#'
#' @export
#' @examples
#' txt <- c(
#'   "Dr. Jane Doe (MRN: 884210) emailed jane.doe@clinic.org on 2026-04-12.",
#'   "Call (555) 234-5678 regarding 742 Evergreen Terrace."
#' )
#' pii_detect(txt)
pii_detect <- function(text, config = pii_config(), include_values = TRUE) {
  if (!is.character(text)) {
    cli::cli_abort("{.arg text} must be a character vector.", class = "airgap_validation_error")
  }
  if (!inherits(config, "airgap_pii_config")) {
    cli::cli_abort("{.arg config} must be an `airgap_pii_config` object.", class = "airgap_validation_error")
  }
  assert_scalar_logical(include_values, "include_values")

  stopwords <- pii_name_stopwords()
  rows <- list()

  for (i in seq_along(text)) {
    spans <- detect_pii_single(text[i], config = config, stopwords = stopwords)
    if (length(spans) == 0L) next
    for (sp in spans) {
      rows[[length(rows) + 1L]] <- list(
        doc_id = i,
        entity_type = sp$entity_type,
        start = sp$start,
        end = sp$end,
        length = sp$length,
        match = if (include_values) sp$match else "[MASKED]",
        value_hash = substr(hash_to_hex(openssl::sha256(enc2utf8(sp$match))), 1L, 16L)
      )
    }
  }

  if (length(rows) == 0L) {
    return(tibble::tibble(
      doc_id = integer(),
      entity_type = character(),
      start = integer(),
      end = integer(),
      length = integer(),
      match = character(),
      value_hash = character()
    ))
  }

  tibble::tibble(
    doc_id = vapply(rows, `[[`, integer(1L), "doc_id"),
    entity_type = vapply(rows, `[[`, character(1L), "entity_type"),
    start = vapply(rows, `[[`, integer(1L), "start"),
    end = vapply(rows, `[[`, integer(1L), "end"),
    length = vapply(rows, `[[`, integer(1L), "length"),
    match = vapply(rows, `[[`, character(1L), "match"),
    value_hash = vapply(rows, `[[`, character(1L), "value_hash")
  )
}

#' Replace detected spans inside a single string from right to left
#' @noRd
apply_span_replacements <- function(text, spans, repl_vec) {
  if (length(spans) == 0L) return(text)
  out <- text
  for (i in rev(seq_along(spans))) {
    sp <- spans[[i]]
    left <- if (sp$start > 1L) substr(out, 1L, sp$start - 1L) else ""
    right <- if (sp$end < nchar(out)) substr(out, sp$end + 1L, nchar(out)) else ""
    out <- paste0(left, repl_vec[i], right)
  }
  out
}

#' Build an aggregate-only airgap_privacy_report from per-document span lists
#' @noRd
build_privacy_report_from_spans <- function(n_docs, doc_spans, config) {
  has_pii <- vapply(doc_spans, function(s) length(s) > 0L, logical(1L))
  n_with <- sum(has_pii)
  pct_with <- if (n_docs > 0L) round(100 * n_with / n_docs, 2) else 0

  all_types <- unlist(lapply(doc_spans, function(s) vapply(s, `[[`, character(1L), "entity_type")), use.names = FALSE)
  if (length(all_types) == 0L) {
    by_ent <- tibble::tibble(
      entity_type = character(),
      count = integer(),
      n_documents = integer(),
      pct_documents = numeric()
    )
    total_ent <- 0L
  } else {
    uniq_types <- sort(unique(all_types))
    counts <- vapply(uniq_types, function(tp) sum(all_types == tp), integer(1L))
    n_doc_tp <- vapply(uniq_types, function(tp) {
      sum(vapply(doc_spans, function(s) any(vapply(s, `[[`, character(1L), "entity_type") == tp), logical(1L)))
    }, integer(1L))
    pct_doc_tp <- if (n_docs > 0L) round(100 * n_doc_tp / n_docs, 2) else rep(0, length(uniq_types))
    by_ent <- tibble::tibble(
      entity_type = uniq_types,
      count = as.integer(counts),
      n_documents = as.integer(n_doc_tp),
      pct_documents = pct_doc_tp
    )
    total_ent <- as.integer(length(all_types))
  }

  structure(
    list(
      n_documents = as.integer(n_docs),
      n_documents_with_pii = as.integer(n_with),
      pct_documents_with_pii = pct_with,
      total_entities = total_ent,
      by_entity = by_ent,
      config_digest = config$config_digest,
      generated_at = utc_timestamp()
    ),
    class = "airgap_privacy_report"
  )
}

#' @export
print.airgap_privacy_report <- function(x, ...) {
  cat("<airgap_privacy_report> (aggregate counts only; zero raw PII)\n")
  cat("  Documents scanned:  ", x$n_documents, "\n", sep = "")
  cat("  Documents with PII: ", x$n_documents_with_pii, " (", x$pct_documents_with_pii, "%)\n", sep = "")
  cat("  Total detections:   ", x$total_entities, "\n", sep = "")
  if (nrow(x$by_entity) > 0L) {
    cat("  By entity type:\n")
    for (i in seq_len(nrow(x$by_entity))) {
      r <- x$by_entity[i, , drop = FALSE]
      cat("    - ", r$entity_type, ": ", r$count, " (", r$n_documents, " docs, ", r$pct_documents, "%)\n", sep = "")
    }
  }
  invisible(x)
}

#' Generate a Pre-Run Privacy Coverage Report Without Leaking Raw PII
#'
#' Scans a character vector, data frame text column, or pseudonymized result
#' and returns aggregate PII detection counts and document coverage rates by
#' entity type. Raw input text and matched sensitive values are strictly
#' excluded from the returned object.
#'
#' @param x A character vector, a data frame (requiring `text_col`), or an
#'   `airgap_pseudonymized` object.
#' @param config An [pii_config()] configuration object.
#' @param text_col Character scalar column name when `x` is a data frame.
#'
#' @return An S3 object of class `"airgap_privacy_report"` containing only
#'   aggregate counts (`n_documents`, `n_documents_with_pii`,
#'   `pct_documents_with_pii`, `total_entities`, `by_entity`, `config_digest`,
#'   `generated_at`).
#'
#' @export
#' @examples
#' notes <- c("Contact Dr. Alice Smith at alice@hospital.org.", "No identifiers here.")
#' pii_privacy_report(notes)
pii_privacy_report <- function(x, config = pii_config(), text_col = NULL) {
  if (inherits(x, "airgap_pseudonymized")) {
    return(x$report)
  }
  if (is.data.frame(x)) {
    if (is.null(text_col)) {
      cli::cli_abort("Specify {.arg text_col} when calling `pii_privacy_report()` on a data frame.", class = "airgap_validation_error")
    }
    assert_scalar_string(text_col, "text_col")
    if (!text_col %in% names(x)) {
      cli::cli_abort("Column {.val {text_col}} not found in data frame.", class = "airgap_validation_error")
    }
    x <- as.character(x[[text_col]])
  }
  if (!is.character(x)) {
    cli::cli_abort("{.arg x} must be a character vector, data frame, or `airgap_pseudonymized` object.", class = "airgap_validation_error")
  }
  if (!inherits(config, "airgap_pii_config")) {
    cli::cli_abort("{.arg config} must be an `airgap_pii_config` object.", class = "airgap_validation_error")
  }

  stopwords <- pii_name_stopwords()
  doc_spans <- lapply(x, detect_pii_single, config = config, stopwords = stopwords)
  build_privacy_report_from_spans(length(x), doc_spans, config)
}

#' Redact Detected PII Entities from Text
#'
#' Deterministically replaces detected PII spans with non-reversible typed
#' placeholders (default `"[REDACTED_{TYPE}]"`). Preserves `NA_character_`
#' elements and attaches an aggregate-only `"pii_report"` attribute containing
#' zero raw sensitive values.
#'
#' @param text Character vector of documents to redact.
#' @param config An [pii_config()] configuration object.
#' @param replacement Character scalar replacement template. `{TYPE}` is
#'   substituted with the uppercased entity type (e.g., `"[REDACTED_EMAIL]"`).
#' @param return_details Logical scalar; if `TRUE`, returns a list with
#'   `text` and `report` (`airgap_privacy_report`); if `FALSE` (default),
#'   returns the redacted character vector with `attr(out, "pii_report")`.
#'
#' @return A redacted character vector (or list when `return_details = TRUE`).
#'
#' @export
#' @examples
#' pii_redact("Patient: Jane Doe (SSN 123-45-6789) emailed jane@example.org.")
pii_redact <- function(
  text,
  config = pii_config(),
  replacement = "[REDACTED_{TYPE}]",
  return_details = FALSE
) {
  if (!is.character(text)) {
    cli::cli_abort("{.arg text} must be a character vector.", class = "airgap_validation_error")
  }
  if (!inherits(config, "airgap_pii_config")) {
    cli::cli_abort("{.arg config} must be an `airgap_pii_config` object.", class = "airgap_validation_error")
  }
  assert_scalar_string(replacement, "replacement", allow_empty = TRUE)
  assert_scalar_logical(return_details, "return_details")

  stopwords <- pii_name_stopwords()
  doc_spans <- vector("list", length(text))
  redacted <- text

  for (i in seq_along(text)) {
    if (is.na(text[i])) {
      doc_spans[[i]] <- list()
      next
    }
    spans <- detect_pii_single(text[i], config = config, stopwords = stopwords)
    doc_spans[[i]] <- spans
    if (length(spans) > 0L) {
      repls <- vapply(spans, function(sp) {
        gsub("{TYPE}", toupper(sp$entity_type), replacement, fixed = TRUE)
      }, character(1L))
      redacted[i] <- apply_span_replacements(text[i], spans, repls)
    }
  }

  report <- build_privacy_report_from_spans(length(text), doc_spans, config)

  if (isTRUE(return_details)) {
    return(list(text = redacted, report = report))
  }

  attr(redacted, "pii_report") <- report
  redacted
}

#' Generate a Cryptographic Secret Key for PII Pseudonymization Vaults
#'
#' Generates a cryptographically strong random key via `openssl::rand_bytes()`
#' encoded as a lowercase hexadecimal string (64 hex characters for 32 bytes /
#' 256 bits).
#'
#' @param n_bytes Integer number of random bytes (minimum 16, default `32L`).
#'
#' @return Character scalar hexadecimal secret key.
#'
#' @export
#' @examples
#' key <- pii_vault_key()
#' nchar(key)
pii_vault_key <- function(n_bytes = 32L) {
  if (!is.numeric(n_bytes) || length(n_bytes) != 1L || is.na(n_bytes) || n_bytes < 16 || n_bytes != floor(n_bytes)) {
    cli::cli_abort("{.arg n_bytes} must be an integer >= 16.", class = "airgap_validation_error")
  }
  paste(as.character(openssl::rand_bytes(as.integer(n_bytes))), collapse = "")
}

#' Create an empty or hydrated PII mapping vault object
#' @noRd
new_pii_vault <- function(key_fingerprint, mappings = list(), vault_id = generate_run_id("vault")) {
  structure(
    list(
      vault_id = vault_id,
      key_fingerprint = key_fingerprint,
      created_at = utc_timestamp(),
      mappings = mappings
    ),
    class = "airgap_pii_vault"
  )
}

#' @export
print.airgap_pii_vault <- function(x, ...) {
  # Strictly NEVER print raw sensitive values to the console!
  cat("<airgap_pii_vault> (sensitive mappings hidden)\n")
  cat("  Vault ID:        ", x$vault_id, "\n", sep = "")
  cat("  Key fingerprint: ", x$key_fingerprint, "\n", sep = "")
  cat("  Stored tokens:   ", length(x$mappings), "\n", sep = "")
  if (length(x$mappings) > 0L) {
    types <- vapply(x$mappings, `[[`, character(1L), "entity_type")
    tbl <- table(types)
    summary_str <- paste(paste0(names(tbl), "=", as.integer(tbl)), collapse = ", ")
    cat("  By entity type:  ", summary_str, "\n", sep = "")
  }
  invisible(x)
}

#' Derive separate encryption and MAC keys from a master secret key
#' @noRd
derive_vault_subkeys <- function(key) {
  master <- normalize_secret_key(key)
  enc_key <- as.raw(openssl::sha256(c(master, charToRaw("|airgapllm-vault-enc-v1"))))
  mac_key <- as.raw(openssl::sha256(c(master, charToRaw("|airgapllm-vault-mac-v1"))))
  fp <- substr(hash_to_hex(openssl::sha256(master)), 1L, 16L)
  list(master = master, enc_key = enc_key, mac_key = mac_key, fingerprint = fp)
}

#' Save a PII Pseudonymization Vault to a Separate Local File
#'
#' Persists an `airgap_pii_vault` to disk separately from model prompts and
#' audit logs. When `encrypt = TRUE` (the default), serializes the vault with
#' AES-256-CBC encryption and Encrypt-then-MAC HMAC-SHA256 authentication, and
#' restricts file permissions to owner-only (`0600`).
#'
#' @param vault An `airgap_pii_vault` object (e.g., from
#'   `pii_pseudonymize()$vault`).
#' @param path Character scalar destination file path.
#' @param key Secret key (required when `encrypt = TRUE`).
#' @param encrypt Logical scalar; encrypt vault at rest. Defaults to `TRUE`.
#'
#' @return Invisibly returns `path`.
#'
#' @export
#' @examples
#' key <- pii_vault_key()
#' p <- pii_pseudonymize("Email jane@example.org", key = key)
#' vf <- tempfile(fileext = ".vault.json")
#' pii_vault_save(p$vault, vf, key = key)
#' loaded <- pii_vault_load(vf, key = key)
#' unlink(vf)
pii_vault_save <- function(vault, path, key = NULL, encrypt = TRUE) {
  if (!inherits(vault, "airgap_pii_vault")) {
    cli::cli_abort("{.arg vault} must be an `airgap_pii_vault` object.", class = "airgap_validation_error")
  }
  assert_scalar_string(path, "path")
  assert_scalar_logical(encrypt, "encrypt")

  payload_json <- canonical_json(list(
    vault_id = vault$vault_id,
    key_fingerprint = vault$key_fingerprint,
    created_at = vault$created_at,
    mappings = vault$mappings
  ))

  if (isTRUE(encrypt)) {
    if (is.null(key)) {
      cli::cli_abort("{.arg key} is required to save an encrypted PII vault.", class = "airgap_key_error")
    }
    subkeys <- derive_vault_subkeys(key)
    if (!identical(subkeys$fingerprint, vault$key_fingerprint)) {
      cli::cli_abort(
        "Provided {.arg key} fingerprint does not match the vault's key fingerprint.",
        class = "airgap_key_error"
      )
    }
    iv <- openssl::rand_bytes(16L)
    ct <- openssl::aes_cbc_encrypt(charToRaw(enc2utf8(payload_json)), key = subkeys$enc_key, iv = iv)
    mac <- hash_to_hex(openssl::sha256(c(iv, ct), key = subkeys$mac_key))

    envelope <- list(
      format = "airgapllm_vault_v1",
      encrypted = TRUE,
      cipher = "aes-256-cbc-hmac-sha256",
      vault_id = vault$vault_id,
      key_fingerprint = vault$key_fingerprint,
      iv_b64 = openssl::base64_encode(iv),
      ciphertext_b64 = openssl::base64_encode(ct),
      mac_hex = mac
    )
    out_text <- jsonlite::toJSON(envelope, auto_unbox = TRUE, pretty = TRUE)
  } else {
    envelope <- list(
      format = "airgapllm_vault_v1",
      encrypted = FALSE,
      vault_id = vault$vault_id,
      key_fingerprint = vault$key_fingerprint,
      created_at = vault$created_at,
      mappings = vault$mappings
    )
    out_text <- jsonlite::toJSON(envelope, auto_unbox = TRUE, pretty = TRUE)
  }

  dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE)
  tmp_path <- paste0(path, ".tmp.", Sys.getpid())
  writeLines(as.character(out_text), con = tmp_path, useBytes = TRUE)
  suppressWarnings(Sys.chmod(tmp_path, mode = "0600"))
  file.rename(tmp_path, path)
  suppressWarnings(Sys.chmod(path, mode = "0600"))
  invisible(path)
}

#' Load a Saved PII Pseudonymization Vault from Disk
#'
#' Reads and (if encrypted) authenticates and decrypts an `airgap_pii_vault`
#' file written by [pii_vault_save()]. Verifies the HMAC-SHA256 authentication
#' tag prior to decryption to reject wrong keys or tampered vault files.
#'
#' @param path Character scalar path to the vault file.
#' @param key Secret key (required when the vault file is encrypted).
#'
#' @return An `airgap_pii_vault` object.
#'
#' @export
pii_vault_load <- function(path, key = NULL) {
  assert_scalar_string(path, "path")
  if (!file.exists(path)) {
    cli::cli_abort("Vault file not found: {.path {path}}.", class = "airgap_vault_error")
  }
  env <- tryCatch(
    jsonlite::fromJSON(path, simplifyVector = FALSE),
    error = function(e) {
      cli::cli_abort("Failed to parse vault JSON: {conditionMessage(e)}", class = "airgap_vault_error")
    }
  )
  if (!identical(env$format, "airgapllm_vault_v1")) {
    cli::cli_abort("Unsupported or invalid vault file format.", class = "airgap_vault_error")
  }

  if (isTRUE(env$encrypted)) {
    if (is.null(key)) {
      cli::cli_abort("{.arg key} is required to decrypt this PII vault.", class = "airgap_key_error")
    }
    subkeys <- derive_vault_subkeys(key)
    iv <- openssl::base64_decode(env$iv_b64)
    ct <- openssl::base64_decode(env$ciphertext_b64)
    expected_mac <- hash_to_hex(openssl::sha256(c(iv, ct), key = subkeys$mac_key))
    if (!identical(tolower(expected_mac), tolower(env$mac_hex))) {
      cli::cli_abort(
        "Vault authentication failed: invalid key or tampered vault ciphertext.",
        class = "airgap_vault_error"
      )
    }
    pt_raw <- tryCatch(
      openssl::aes_cbc_decrypt(ct, key = subkeys$enc_key, iv = iv),
      error = function(e) {
        cli::cli_abort("Vault decryption failed: {conditionMessage(e)}", class = "airgap_vault_error")
      }
    )
    inner <- jsonlite::fromJSON(rawToChar(pt_raw), simplifyVector = FALSE)
    return(structure(
      list(
        vault_id = inner$vault_id,
        key_fingerprint = inner$key_fingerprint,
        created_at = inner$created_at,
        mappings = inner$mappings %||% list()
      ),
      class = "airgap_pii_vault"
    ))
  }

  structure(
    list(
      vault_id = env$vault_id,
      key_fingerprint = env$key_fingerprint,
      created_at = env$created_at,
      mappings = env$mappings %||% list()
    ),
    class = "airgap_pii_vault"
  )
}

#' Keyed Deterministic Reversible PII Pseudonymization (HMAC-SHA256)
#'
#' Replaces detected PII entities with deterministic HMAC-SHA256 keyed
#' pseudonym tokens (e.g., `<<PERSON_NAME_a3f81c920b>>`) so the same sensitive
#' value maps consistently across documents while keeping original identifiers
#' isolated in a separate local mapping vault (`airgap_pii_vault`).
#'
#' @param text Character vector of documents to pseudonymize.
#' @param key Secret key (character string or raw vector, e.g., from
#'   [pii_vault_key()]).
#' @param config An [pii_config()] configuration object.
#' @param vault Optional existing `airgap_pii_vault` created with the same
#'   `key` to accumulate mappings across batches.
#' @param vault_path Optional file path where the mapping vault is immediately
#'   saved via [pii_vault_save()].
#' @param encrypt_vault Logical scalar; encrypt saved vault file when
#'   `vault_path` is provided. Defaults to `TRUE`.
#' @param token_length Integer number of hex characters (8 to 32) from the
#'   HMAC-SHA256 digest used in each pseudonym token. Defaults to `10L`.
#'
#' @return An S3 object of class `"airgap_pseudonymized"` with elements:
#'   - `text`: pseudonymized character vector
#'   - `vault`: separate `airgap_pii_vault` mapping tokens back to raw values
#'   - `report`: aggregate-only `airgap_privacy_report` (zero raw PII)
#'   - `vault_path`: saved vault path or `NULL`
#'
#' @export
#' @examples
#' key <- pii_vault_key()
#' docs <- c("Dr. Jane Doe called (555) 234-5678.", "Follow-up with Dr. Jane Doe.")
#' res <- pii_pseudonymize(docs, key = key)
#' res$text
#' pii_reidentify(res$text, res$vault)
pii_pseudonymize <- function(
  text,
  key,
  config = pii_config(),
  vault = NULL,
  vault_path = NULL,
  encrypt_vault = TRUE,
  token_length = 10L
) {
  if (!is.character(text)) {
    cli::cli_abort("{.arg text} must be a character vector.", class = "airgap_validation_error")
  }
  if (!inherits(config, "airgap_pii_config")) {
    cli::cli_abort("{.arg config} must be an `airgap_pii_config` object.", class = "airgap_validation_error")
  }
  if (!is.numeric(token_length) || length(token_length) != 1L || is.na(token_length) ||
      token_length < 8 || token_length > 32 || token_length != floor(token_length)) {
    cli::cli_abort("{.arg token_length} must be an integer between 8 and 32.", class = "airgap_validation_error")
  }
  token_length <- as.integer(token_length)
  assert_scalar_logical(encrypt_vault, "encrypt_vault")

  subkeys <- derive_vault_subkeys(key)

  if (is.null(vault)) {
    vault <- new_pii_vault(key_fingerprint = subkeys$fingerprint)
  } else {
    if (!inherits(vault, "airgap_pii_vault")) {
      cli::cli_abort("{.arg vault} must be an `airgap_pii_vault` object.", class = "airgap_validation_error")
    }
    if (!identical(vault$key_fingerprint, subkeys$fingerprint)) {
      cli::cli_abort(
        "Key fingerprint mismatch: cannot mix keys within the same pseudonymization vault.",
        class = "airgap_key_error"
      )
    }
  }

  stopwords <- pii_name_stopwords()
  doc_spans <- vector("list", length(text))
  pseudo_text <- text
  mappings <- vault$mappings

  for (i in seq_along(text)) {
    if (is.na(text[i])) {
      doc_spans[[i]] <- list()
      next
    }
    spans <- detect_pii_single(text[i], config = config, stopwords = stopwords)
    doc_spans[[i]] <- spans
    if (length(spans) > 0L) {
      repls <- character(length(spans))
      for (j in seq_along(spans)) {
        sp <- spans[[j]]
        mac_input <- paste0(sp$entity_type, "\x1f", sp$match)
        digest_hex <- hmac_sha256_hex(mac_input, subkeys$master)
        tok <- paste0("<<", toupper(sp$entity_type), "_", substr(digest_hex, 1L, token_length), ">>")
        if (is.null(mappings[[tok]])) {
          mappings[[tok]] <- list(entity_type = sp$entity_type, value = sp$match)
        }
        repls[j] <- tok
      }
      pseudo_text[i] <- apply_span_replacements(text[i], spans, repls)
    }
  }

  vault$mappings <- mappings
  report <- build_privacy_report_from_spans(length(text), doc_spans, config)

  if (!is.null(vault_path)) {
    pii_vault_save(vault, path = vault_path, key = key, encrypt = encrypt_vault)
  }

  structure(
    list(
      text = pseudo_text,
      vault = vault,
      report = report,
      vault_path = vault_path
    ),
    class = "airgap_pseudonymized"
  )
}

#' @export
print.airgap_pseudonymized <- function(x, ...) {
  cat("<airgap_pseudonymized>\n")
  cat("  Documents:      ", length(x$text), "\n", sep = "")
  cat("  Unique tokens:  ", length(x$vault$mappings), "\n", sep = "")
  cat("  Total entities: ", x$report$total_entities, "\n", sep = "")
  if (!is.null(x$vault_path)) {
    cat("  Vault saved at: ", x$vault_path, "\n", sep = "")
  }
  invisible(x)
}

#' Re-Identify Pseudonymized Text Using a Local Mapping Vault
#'
#' Restores original values for `<<TYPE_HASH>>` pseudonym tokens using an
#' in-memory `airgap_pii_vault` or a vault file saved on disk via
#' [pii_vault_save()].
#'
#' @param text Character vector (or data frame when `cols` is supplied)
#'   containing pseudonymized strings.
#' @param vault An `airgap_pii_vault` object, an `airgap_pseudonymized` object,
#'   or a file path to a saved vault file.
#' @param key Optional secret key required when `vault` is a path to an
#'   encrypted vault file.
#' @param cols Optional character vector of column names to re-identify when
#'   `text` is a data frame. Defaults to all character columns.
#'
#' @return A character vector (or data frame) with matching pseudonym tokens
#'   restored to their original values.
#'
#' @export
#' @examples
#' key <- pii_vault_key()
#' orig <- "Patient: Jane Doe (jane@example.org)"
#' res <- pii_pseudonymize(orig, key = key)
#' identical(pii_reidentify(res$text, res$vault), orig)
pii_reidentify <- function(text, vault, key = NULL, cols = NULL) {
  if (inherits(vault, "airgap_pseudonymized")) {
    vault <- vault$vault
  } else if (is.character(vault) && length(vault) == 1L) {
    vault <- pii_vault_load(vault, key = key)
  }
  if (!inherits(vault, "airgap_pii_vault")) {
    cli::cli_abort(
      "{.arg vault} must be an `airgap_pii_vault`, `airgap_pseudonymized`, or file path.",
      class = "airgap_validation_error"
    )
  }

  reid_vec <- function(vec) {
    if (!is.character(vec) || length(vec) == 0L || length(vault$mappings) == 0L) {
      return(vec)
    }
    toks <- names(vault$mappings)
    out <- vec
    for (i in seq_along(out)) {
      if (is.na(out[i]) || !grepl("<<[A-Z0-9_]+_[0-9a-f]{8,32}>>", out[i], perl = TRUE)) {
        next
      }
      s <- out[i]
      for (tok in toks) {
        if (grepl(tok, s, fixed = TRUE)) {
          s <- gsub(tok, vault$mappings[[tok]]$value, s, fixed = TRUE)
        }
      }
      out[i] <- s
    }
    out
  }

  if (is.data.frame(text)) {
    target_cols <- cols %||% names(text)[vapply(text, is.character, logical(1L))]
    missing_cols <- setdiff(target_cols, names(text))
    if (length(missing_cols) > 0L) {
      cli::cli_abort("Column(s) not found in data frame: {paste(missing_cols, collapse = ', ')}.", class = "airgap_validation_error")
    }
    out_df <- text
    for (cl in target_cols) {
      out_df[[cl]] <- reid_vec(out_df[[cl]])
    }
    return(out_df)
  }

  if (!is.character(text)) {
    cli::cli_abort("{.arg text} must be a character vector or data frame.", class = "airgap_validation_error")
  }
  reid_vec(text)
}
