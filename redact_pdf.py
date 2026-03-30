#!/usr/bin/env python3
"""
redact_pdf.py — Redact PII from a PDF for safe upload.

Auto-redacts (no flags needed):
  - SSNs (all common formats)
  - ITINs (9XX-XX-XXXX)
  - EINs / Tax IDs (XX-XXXXXXX)
  - Bank account & routing numbers (labeled fields on 1040, W-2, etc.)
  - Phone numbers (US formats)
  - Email addresses
  - Date of birth (label-required — won't touch tax year dates or deadlines)
  - Preparer PTIN (P-XXXXXXXX)
  - IRS Identity Protection PIN (IP PIN, 6-digit labeled)
  - W-2 specific fields (control number, state employer ID, name blocks)

Optional flags:
  -a / --address    Address to redact (repeatable, auto-expands variations)
  -n / --name       Person name to redact (repeatable, matches name variants)
  -o / --output     Output path (default: input_redacted.pdf)
  --dry-run         Show what would be redacted without modifying the file

Also:
  - Strips PDF metadata (author, creator, producer, title, subject, keywords)
  - Scrubs AcroForm field values (interactive form fields)
  - Removes embedded file attachments (TurboTax XML, etc.)
  - Removes non-essential annotations (sticky notes, comments, free text)
  - Removes digital signatures, JavaScript, bookmarks, and link URIs

Usage:
    python redact_pdf.py input.pdf [-o output.pdf] [--address "..."] [--name "..."]

Requirements:
    pip install pymupdf
"""

import argparse
import functools
import re
import sys
from pathlib import Path

import fitz  # PyMuPDF


# ─── SSN patterns ───────────────────────────────────────────────────────────

_SSN_LABEL = r'(?:ssn|social\s*security(?:\s*(?:number|no|#))?)\s*[:#]?\s*'

# Allowed separators between SSN digit groups: dashes, pipes, spaces,
# dots, box-drawing chars — but NOT commas (which appear in dollar amounts)
_SSN_GAP = r'[\s\-–—|._·•]{1,5}'

SSN_PATTERNS = [
    re.compile(rf'(?<!\d)\d{{3}}{_SSN_GAP}\d{{2}}{_SSN_GAP}\d{{4}}(?!\d)'),
    # Bare 9 consecutive digits — on a tax return, dollar amounts always
    # have commas/decimals so 9 consecutive digits is always an SSN/ITIN/EIN
    re.compile(r'(?<!\d)\d{9}(?!\d)'),
    # Labeled (separator {0,5} covers both formatted and bare 9-digit)
    re.compile(rf'(?i){_SSN_LABEL}\d{{3}}[\s\-–—|._]{{0,5}}\d{{2}}[\s\-–—|._]{{0,5}}\d{{4}}'),
    # Labeled on previous line
    re.compile(rf'(?i){_SSN_LABEL}\n\s*\d{{3}}[\s\-–—|._]{{0,5}}\d{{2}}[\s\-–—|._]{{0,5}}\d{{4}}'),
    # "SSN or ITIN" label (with optional newline before digits)
    re.compile(r'(?i)(?:ssn\s*(?:or\s*)?itin|itin\s*(?:or\s*)?ssn)\s*[:#]?\s*\n?\s*\d{3}[\s\-–—|._]{0,5}\d{2}[\s\-–—|._]{0,5}\d{4}'),
]


# ─── ITIN patterns ─────────────────────────────────────────────────────────
# ITINs: 9XX-XX-XXXX — always start with 9, used by non-resident filers.
# The unlabeled dash format is already caught by SSN_PATTERNS[0], but
# labeled forms and the space-separated variant need ITIN-specific labels.

_ITIN_LABEL = r'(?:itin|individual\s*taxpayer\s*(?:id(?:entification)?)?(?:\s*(?:number|no|#))?)\s*[:#]?\s*'

ITIN_PATTERNS = [
    re.compile(rf'(?<!\d)9\d{{2}}{_SSN_GAP}\d{{2}}{_SSN_GAP}\d{{4}}(?!\d)'),
    re.compile(rf'(?i){_ITIN_LABEL}9\d{{2}}[\s\-–—|._]{{0,5}}\d{{2}}[\s\-–—|._]{{0,5}}\d{{4}}'),
    re.compile(rf'(?i){_ITIN_LABEL}9\d{{8}}(?!\d)'),
]


# ─── EIN / Tax ID patterns ──────────────────────────────────────────────────

_EIN_LABEL = (
    r'(?:ein|employer\s*id(?:entification)?(?:\s*(?:number|no|#))?'
    r'|tax\s*(?:id|identification)(?:\s*(?:number|no|#))?'
    r'|(?:federal\s*)?(?:tax\s*)?id(?:\s*(?:number|no|#))?'
    r'|fein|tin)\s*[:#]?\s*'
)

EIN_PATTERNS = [
    # Labeled only — bare XX-XXXXXXX matches too many form references
    re.compile(rf'(?i){_EIN_LABEL}\d{{2}}[-–—]?\d{{7}}(?!\d)'),
]


# ─── Bank account & routing number patterns ─────────────────────────────────
# Require a label prefix to avoid false positives on random digit runs.
# Covers 1040 line 35b/35d, W-2 boxes, direct deposit forms.

BANK_PATTERNS = [
    re.compile(
        r'(?i)(?:routing|transit|aba|rtn)(?:\s*(?:number|no|#|num))?\s*[:#]?\s*'
        r'\d{9}(?!\d)'
    ),
    re.compile(
        r'(?i)(?:account|acct|acct\.)(?:\s*(?:number|no|#|num))?\s*[:#]?\s*'
        r'\d{4,17}(?!\d)'
    ),
    re.compile(r'(?i)(?:routing|account|acct)\s*:\s*\d{4,17}(?!\d)'),
    re.compile(
        r'(?i)\b[bd]\s+(?:routing|account)\s*(?:number|no|#)?\s*\d{4,17}(?!\d)'
    ),
    re.compile(
        r'(?i)(?:direct\s*deposit|bank\s*account|checking|savings)'
        r'(?:\s*(?:number|no|#|num|acct))?\s*[:#]?\s*\d{4,17}(?!\d)'
    ),
]


# ─── Phone number patterns ─────────────────────────────────────────────────

_PHONE_LABEL = r'(?:phone|tel(?:ephone)?|cell|mobile|fax|contact)\s*(?:number|no|#|num)?\s*[:#]?\s*'

PHONE_PATTERNS = [
    # (XXX) XXX-XXXX with optional +1 prefix
    re.compile(r'(?:\+?1[-.\s]?)?\(\d{3}\)\s*[-.]?\s*\d{3}[-.\s]\d{4}(?!\d)'),
    # XXX-XXX-XXXX / XXX.XXX.XXXX / XXX XXX XXXX with optional +1 prefix
    re.compile(r'(?:\+?1[-.\s]?)?\b\d{3}[-.\s]\d{3}[-.\s]\d{4}(?!\d)'),
    # Labeled: phone: XXXXXXXXXX (10 consecutive digits)
    re.compile(rf'(?i){_PHONE_LABEL}(?:\+?1[-.\s]?)?\d{{10}}(?!\d)'),
    # Labeled with any format
    re.compile(rf'(?i){_PHONE_LABEL}(?:\+?1[-.\s]?)?\(?\d{{3}}\)?[-.\s]?\d{{3}}[-.\s]?\d{{4}}'),
]


# ─── Email patterns ────────────────────────────────────────────────────────

EMAIL_PATTERNS = [
    re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
]


# ─── W-2 specific patterns ─────────────────────────────────────────────────
# Fields unique to W-2 that aren't caught by other pattern groups.

W2_PATTERNS = [
    # Box d: Control number (alphanumeric, employer-specific)
    re.compile(r'(?i)(?:control\s*(?:number|no|#|num))\s*[:#]?\s*[A-Za-z0-9\-]{4,20}'),
    # Box 15: State / Employer's state ID number
    re.compile(r'(?i)(?:state\s*(?:employer(?:\'?s)?\s*)?(?:id|identification)(?:\s*(?:number|no|#))?|employer(?:\'?s)?\s*state\s*(?:id|no|#|number))\s*[:#]?\s*[A-Za-z0-9\-]{4,20}'),
    # Box a labeled on W-2: "Employee's social security number" (already caught by SSN,
    # but the W-2 sometimes has "a Employee's SSN" with box letter prefix)
    re.compile(r'(?i)\ba\s+employee(?:\'?s)?\s+(?:ssn|social\s*security)\s*(?:number|no|#)?\s*\d{3}[-–—\s]?\d{2}[-–—\s]?\d{4}'),
    # Employer name + address block: "c Employer's name, address, and ZIP code"
    # followed by multi-line content — we match the label + the first non-empty line after it
    re.compile(r'(?i)(?:employer(?:\'?s)?\s*name(?:\s*,?\s*address)?(?:\s*,?\s*(?:and\s*)?zip\s*code)?)\s*[:#]?\s*\S[^\n]{3,80}'),
    # Employee name block: "e Employee's first name and initial  Last name  Suff."
    re.compile(r'(?i)(?:employee(?:\'?s)?\s*(?:first\s*)?name(?:\s*(?:and|&)\s*(?:initial|last))?)\s*[:#]?\s*\S[^\n]{3,80}'),
]


# ─── Date of birth patterns ───────────────────────────────────────────────
# ONLY match dates preceded by a DOB/birth label to avoid redacting
# tax year dates, filing deadlines, pay period dates, etc.

_DOB_LABEL = (
    r'(?:d\.?o\.?b\.?|date\s*of\s*birth|birth\s*date|born|birthday)'
    r'\s*[:#]?\s*'
)
_DATE_FORMATS = (
    r'(?:'
    r'\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}'   # MM/DD/YYYY, M/D/YY, etc.
    r'|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{2,4}'  # Jan 1, 1990
    r'|\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+\d{2,4}'   # 1 Jan 1990
    r')'
)

DOB_PATTERNS = [
    re.compile(rf'(?i){_DOB_LABEL}{_DATE_FORMATS}'),
]


# ─── Preparer PTIN patterns ──────────────────────────────────────────────
# Preparer Tax Identification Number: P-XXXXXXXX (P + 8 digits)

PTIN_PATTERNS = [
    re.compile(r'\bP[-–]?\d{8}\b'),
    re.compile(r'(?i)(?:ptin|preparer\s*(?:tax\s*)?(?:id(?:entification)?)?(?:\s*(?:number|no|#))?)\s*[:#]?\s*P?[-–]?\d{8}(?!\d)'),
]


# ─── IRS Identity Protection PIN patterns ─────────────────────────────────
# IP PIN: 6-digit number, always labeled on forms

_IP_PIN_LABEL = (
    r'(?:ip\s*pin|identity\s*protection\s*(?:pin|personal\s*identification\s*number))'
    r'\s*[:#]?\s*'
)

IP_PIN_PATTERNS = [
    re.compile(rf'(?i){_IP_PIN_LABEL}\d{{6}}(?!\d)'),
]


# ─── Address expansion ──────────────────────────────────────────────────────

STREET_ABBREVS = {
    "street":     ["st", "st.", "str"],
    "avenue":     ["ave", "ave.", "av"],
    "boulevard":  ["blvd", "blvd.", "blv"],
    "drive":      ["dr", "dr.", "drv"],
    "lane":       ["ln", "ln.", "la"],
    "road":       ["rd", "rd.", "roa"],
    "court":      ["ct", "ct.", "crt"],
    "circle":     ["cir", "cir.", "circ"],
    "place":      ["pl", "pl.", "plc"],
    "terrace":    ["ter", "ter.", "terr", "terr."],
    "way":        ["wy", "wy."],
    "trail":      ["trl", "trl.", "tr"],
    "parkway":    ["pkwy", "pkwy.", "pky"],
    "highway":    ["hwy", "hwy.", "hw"],
    "expressway": ["expy", "expy.", "exp"],
    "suite":      ["ste", "ste.", "su"],
    "apartment":  ["apt", "apt.", "ap"],
    "unit":       ["un", "un."],
    "building":   ["bldg", "bldg.", "bld"],
    "floor":      ["fl", "fl.", "flr"],
    "north":      ["n", "n."],
    "south":      ["s", "s."],
    "east":       ["e", "e."],
    "west":       ["w", "w."],
    "northeast":  ["ne", "n.e.", "n.e"],
    "northwest":  ["nw", "n.w.", "n.w"],
    "southeast":  ["se", "s.e.", "s.e"],
    "southwest":  ["sw", "s.w.", "s.w"],
}

DIRECTIONAL_WORDS = {"north", "south", "east", "west",
                      "northeast", "northwest", "southeast", "southwest"}

UNIT_DESIGNATORS = {"suite", "apartment", "unit", "building", "floor"}

ABBREV_TO_CANONICAL = {}
for canonical, abbrevs in STREET_ABBREVS.items():
    for a in abbrevs:
        ABBREV_TO_CANONICAL[a.lower()] = canonical
    ABBREV_TO_CANONICAL[canonical.lower()] = canonical

STATE_ABBREVS = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas",
    "CA": "California", "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware",
    "FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho",
    "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas",
    "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi",
    "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
    "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York",
    "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah",
    "VT": "Vermont", "VA": "Virginia", "WA": "Washington", "WV": "West Virginia",
    "WI": "Wisconsin", "WY": "Wyoming", "DC": "District of Columbia",
}
STATE_NAME_TO_ABBREV = {v.lower(): k for k, v in STATE_ABBREVS.items()}


def normalize_token(token: str) -> str:
    """Map a token to its canonical form if it's a known abbreviation."""
    t = token.lower().rstrip(".,")
    return ABBREV_TO_CANONICAL.get(t, t)


@functools.lru_cache(maxsize=256)
def get_all_forms(token: str) -> tuple[str, ...]:
    """Return all surface forms of a token (canonical + abbreviations)."""
    canon = normalize_token(token)
    forms = {canon}
    if canon in STREET_ABBREVS:
        forms.update(STREET_ABBREVS[canon])
    if canon in STATE_NAME_TO_ABBREV:
        forms.add(STATE_NAME_TO_ABBREV[canon].lower())
    upper = token.upper()
    if upper in STATE_ABBREVS:
        forms.add(STATE_ABBREVS[upper].lower())
        forms.add(upper.lower())
    forms.add(token.lower())
    return tuple(sorted(forms, key=len, reverse=True))


def _token_to_regex_part(token: str) -> str:
    """Convert a token into a regex fragment matching all its known forms."""
    forms = get_all_forms(token)
    if len(forms) == 1:
        return re.escape(forms[0])
    return "(?:" + "|".join(re.escape(f) for f in forms) + ")\\.?"


def build_address_patterns(address: str) -> list[re.Pattern]:
    """
    Build regex patterns that match many variations of the address.

    Strategy:
    1. Tokenize the address.
    2. For each token, build an alternation of all known surface forms.
    3. Allow flexible whitespace/punctuation between tokens.
    4. Also build sub-patterns for meaningful fragments (street line, city/state/zip).
    5. Handle unit-letter-appended-to-house-number ("1936A" for "1936 Unit A").
    """
    clean = re.sub(r'[,;]+', ' ', address)
    tokens = clean.split()

    if not tokens:
        return []

    patterns = []
    sep = r'[\s,;\-]{0,3}'

    # Detect house number (first token if numeric) and unit designator + value
    house_num = tokens[0] if tokens[0].isdigit() else None
    unit_idx = None
    unit_value = None
    for i, tok in enumerate(tokens):
        if normalize_token(tok) in UNIT_DESIGNATORS and i + 1 < len(tokens):
            unit_idx = i
            unit_value = tokens[i + 1]
            break

    def _make_parts(token_list):
        parts = []
        for tok in token_list:
            part = _token_to_regex_part(tok)
            if re.match(r'^\d{5}(-\d{4})?$', tok):
                part += r'(?:[-–]\d{4})?'
            parts.append(part)
        return parts

    # --- Full address pattern ---
    full_parts = _make_parts(tokens)
    patterns.append(re.compile(sep.join(full_parts), re.IGNORECASE))

    # --- Variant: unit value appended to house number (e.g. "1936A 10th Ave W") ---
    # Skip the unit designator + value tokens, allow letter suffix on house number
    if house_num and unit_value and len(unit_value) <= 2 and unit_idx is not None:
        condensed_tokens = (
            tokens[:unit_idx] + tokens[unit_idx + 2:]
        )
        condensed_parts = _make_parts(condensed_tokens)
        # Replace house number part with version that allows optional letter suffix
        condensed_parts[0] = re.escape(house_num) + r'[A-Za-z]?'
        patterns.append(re.compile(sep.join(condensed_parts), re.IGNORECASE))

    # --- Street line (up to and including street type + trailing directional) ---
    street_type_indices = [
        i for i, tok in enumerate(tokens)
        if normalize_token(tok) in STREET_ABBREVS
        and normalize_token(tok) not in DIRECTIONAL_WORDS
        and normalize_token(tok) not in UNIT_DESIGNATORS
    ]

    if street_type_indices:
        last_st = street_type_indices[-1]

        # Street line without directional suffix: "1936 10th Ave"
        base_street_parts = _make_parts(tokens[:last_st + 1])
        patterns.append(re.compile(sep.join(base_street_parts), re.IGNORECASE))

        # Include trailing directional words (N/S/E/W): "1936 10th Ave W"
        street_end = last_st + 1
        while (street_end < len(tokens)
               and normalize_token(tokens[street_end]) in DIRECTIONAL_WORDS):
            street_end += 1

        if street_end > last_st + 1:
            street_parts = _make_parts(tokens[:street_end])
            street_pattern = sep.join(street_parts)
            patterns.append(re.compile(street_pattern, re.IGNORECASE))
        else:
            street_pattern = sep.join(base_street_parts)

        # Street line with optional unit suffix
        remaining = tokens[street_end:]
        if remaining and normalize_token(remaining[0]) in UNIT_DESIGNATORS:
            u_tokens = remaining[:2] if len(remaining) >= 2 else remaining
            u_parts = _make_parts(u_tokens)
            extended = street_pattern + sep + sep.join(u_parts)
            patterns.append(re.compile(extended, re.IGNORECASE))

        # Street line variant with unit appended to house number
        if house_num and unit_value and len(unit_value) <= 2:
            st_condensed = [t for i, t in enumerate(tokens[:street_end])
                            if i not in (unit_idx, unit_idx + 1)
                            ] if unit_idx is not None and unit_idx < street_end else tokens[:street_end]
            if st_condensed:
                st_cond_parts = _make_parts(st_condensed)
                st_cond_parts[0] = re.escape(house_num) + r'[A-Za-z]?'
                patterns.append(re.compile(sep.join(st_cond_parts), re.IGNORECASE))

    # No standalone zip patterns — bare 5-digit numbers cause false positives
    # on dollar amounts, form line numbers, and other numeric fields.

    return patterns


# ─── Name patterns ───────────────────────────────────────────────────────────

def build_name_patterns(name: str) -> list[re.Pattern]:
    """
    Build regex patterns that match variations of a person's name.

    Given "Samantha Jane Public", generates patterns for:
      - Full name as given
      - Without middle: Samantha Public
      - Last, First: Public, Samantha
      - Last, First Middle: Public, Samantha Jane
      - First initial + Last: S. Public, S Public
      - First + middle initial (tax form "first name and initial"): Samantha J
      - First name alone (4+ chars): Samantha
      - Last name alone (4+ chars): Public
    """
    parts = name.split()
    if not parts:
        return []

    patterns = []
    sep = r'[\s,.\-]{0,4}'

    # Full name as written (flexible separators)
    full = sep.join(re.escape(p) for p in parts)
    patterns.append(re.compile(full, re.IGNORECASE))

    if len(parts) >= 2:
        first = parts[0]
        last = parts[-1]
        middle_parts = parts[1:-1]

        first_esc = re.escape(first)
        last_esc = re.escape(last)

        # First Last (no middle)
        patterns.append(re.compile(
            r'\b' + first_esc + sep + last_esc + r'\b', re.IGNORECASE
        ))

        # Last, First
        patterns.append(re.compile(
            r'\b' + last_esc + r'[\s,]{1,4}' + first_esc + r'\b', re.IGNORECASE
        ))

        # Last, First Middle...
        if middle_parts:
            mid = sep.join(re.escape(p) for p in middle_parts)
            patterns.append(re.compile(
                r'\b' + last_esc + r'[\s,]{1,4}' + first_esc + sep + mid,
                re.IGNORECASE
            ))

        # First initial + Last: "S. Public" or "S Public"
        initial = first[0]
        patterns.append(re.compile(
            r'(?<!\w)' + re.escape(initial) + r'\.?\s' + last_esc,
            re.IGNORECASE
        ))

        # First + middle initial: "Samantha J" / "Samantha J."
        # Common on tax forms ("first name and initial" field)
        if middle_parts:
            mid_initial = middle_parts[0][0]
            patterns.append(re.compile(
                r'\b' + first_esc + r'\s+' + re.escape(mid_initial) + r'\.?\b',
                re.IGNORECASE
            ))

        # First name alone (4+ chars to avoid false positives)
        if len(first) >= 4:
            patterns.append(re.compile(
                r'\b' + first_esc + r'\b', re.IGNORECASE
            ))

        # Last name alone (4+ chars to avoid false positives)
        if len(last) >= 4:
            patterns.append(re.compile(
                r'\b' + last_esc + r'\b', re.IGNORECASE
            ))

    return patterns


# ─── Digit-per-box reconstruction ─────────────────────────────────────────
# IRS forms put SSN/EIN digits in individual boxes. After flattening,
# each digit becomes a separate text span. get_text("text") may return
# them with weird spacing that no regex can reliably match. Instead,
# we use get_text("words") to find single-digit spans, group them by
# vertical position (same row), and check if concatenation matches.

def find_digit_box_sequences(page_words) -> list[tuple[fitz.Rect, str]]:
    """
    Find SSN-like digit sequences from individual digit boxes on a page.

    Looks for exactly 9 single-digit text spans in a tight horizontal
    row (typical of IRS SSN entry boxes). Uses strict spacing to avoid
    matching adjacent dollar-amount fields.

    Returns list of (spanning_rect, concatenated_digits).
    """
    words = page_words
    if not words:
        return []

    # Filter for single-digit words
    digit_words = [
        w for w in words
        if len(w[4].strip()) == 1 and w[4].strip().isdigit()
    ]

    if len(digit_words) < 9:
        return []

    # Sort by y-center then x-position
    digit_words.sort(key=lambda w: (round((w[1] + w[3]) / 2, 0), w[0]))

    # Group digits on the same row with tight spacing (< 15pt gap —
    # digit boxes are ~8-12pt wide with 1-3pt gaps between them;
    # dollar amount fields are much further apart)
    results = []
    group = [digit_words[0]]

    for w in digit_words[1:]:
        prev = group[-1]
        same_row = abs((w[1] + w[3]) / 2 - (prev[1] + prev[3]) / 2) < 5
        close_x = (w[0] - prev[2]) < 15

        if same_row and close_x:
            group.append(w)
        else:
            _check_digit_group(group, results)
            group = [w]

    _check_digit_group(group, results)
    return results


def _check_digit_group(group, results):
    """Check if a group of single-digit words is exactly 9 digits (SSN)."""
    # Only match groups of exactly 9 — not sliding windows across longer
    # runs of digits, which would false-positive on amount fields
    if len(group) != 9:
        return

    digits = "".join(w[4].strip() for w in group)
    if re.match(r'^\d{9}$', digits):
        x0 = min(w[0] for w in group)
        y0 = min(w[1] for w in group)
        x1 = max(w[2] for w in group)
        y1 = max(w[3] for w in group)
        results.append((fitz.Rect(x0, y0, x1, y1), digits))


# ─── Redaction engine ────────────────────────────────────────────────────────

REDACT_LABEL = "[REDACTED]"


def _find_ssn_widget_sequences(all_widgets):
    """
    Find groups of adjacent single-digit widgets that form 9-digit SSNs.

    Returns set of widget indices that should be scrubbed.
    """
    # Collect single-digit widgets with their positions
    digit_widgets = []
    for i, (rect, widget, val) in enumerate(all_widgets):
        v = val.strip()
        if len(v) == 1 and v.isdigit() and rect and not rect.is_empty:
            y_center = (rect.y0 + rect.y1) / 2
            digit_widgets.append((i, rect.x0, rect.x1, y_center, v))

    if len(digit_widgets) < 9:
        return set()

    # Sort by y-center then x
    digit_widgets.sort(key=lambda d: (round(d[3], 0), d[1]))

    # Group into rows of adjacent single-digit widgets
    ssn_indices = set()
    group = [digit_widgets[0]]

    for dw in digit_widgets[1:]:
        prev = group[-1]
        same_row = abs(dw[3] - prev[3]) < 5
        close_x = (dw[1] - prev[2]) < 20

        if same_row and close_x:
            group.append(dw)
        else:
            if len(group) == 9:
                digits = "".join(d[4] for d in group)
                if re.match(r'^\d{9}$', digits):
                    ssn_indices.update(d[0] for d in group)
            group = [dw]

    if len(group) == 9:
        digits = "".join(d[4] for d in group)
        if re.match(r'^\d{9}$', digits):
            ssn_indices.update(d[0] for d in group)

    return ssn_indices


def scrub_page_form_fields(page, all_widgets, pii_patterns: list[re.Pattern]) -> int:
    """
    Destroy form field widgets whose values match PII patterns, plus
    digit-per-box SSN sequences detected by widget position.

    Leaves dollar amounts, checkboxes, and other non-PII fields intact.
    Does NOT call apply_redactions(); the caller handles that.
    """
    if not all_widgets:
        return 0

    # Find digit-per-box SSN sequences by widget position
    ssn_indices = _find_ssn_widget_sequences(all_widgets)

    # Determine which widgets to scrub
    to_scrub_indices = set()
    for i, (rect, widget, val) in enumerate(all_widgets):
        if not val.strip() or not rect or rect.is_empty:
            continue
        # Widget is part of a digit-per-box SSN
        if i in ssn_indices:
            to_scrub_indices.add(i)
        # Widget value matches a PII pattern
        elif any(p.search(val) for p in pii_patterns):
            to_scrub_indices.add(i)

    if not to_scrub_indices:
        return 0

    # Add redaction annotations and delete the widgets
    for i in to_scrub_indices:
        rect, widget, _ = all_widgets[i]
        page.add_redact_annot(rect, text="", fill=(0, 0, 0))

    for i in to_scrub_indices:
        _, widget, _ = all_widgets[i]
        try:
            page.delete_widget(widget)
        except Exception:
            pass

    return len(to_scrub_indices)


def strip_metadata(doc: fitz.Document):
    """Remove document-level metadata that could leak identity info."""
    doc.set_metadata({
        "author": "",
        "creator": "",
        "producer": "",
        "title": "",
        "subject": "",
        "keywords": "",
        "creationDate": "",
        "modDate": "",
    })
    doc.del_xml_metadata()


def strip_embedded_files(doc: fitz.Document) -> int:
    """
    Remove all embedded file attachments from the document.
    Tax software (especially TurboTax) embeds XML data files containing
    the complete structured return data in machine-readable form.
    """
    removed = 0
    try:
        for name in list(doc.embfile_names()):
            doc.embfile_del(name)
            removed += 1
    except Exception:
        pass

    for page in doc:
        for annot in list(page.annots() or []):
            if annot.type[0] == fitz.PDF_ANNOT_FILE_ATTACHMENT:
                page.delete_annot(annot)
                removed += 1
    return removed


def strip_annotations(doc: fitz.Document) -> int:
    """
    Remove non-essential annotations (sticky notes, comments, free text,
    markup, etc.) that could contain sensitive data.
    Preserves links and form widgets.
    """
    KEEP_TYPES = {fitz.PDF_ANNOT_LINK, fitz.PDF_ANNOT_WIDGET}
    removed = 0
    for page in doc:
        for annot in list(page.annots() or []):
            if annot.type[0] not in KEEP_TYPES:
                page.delete_annot(annot)
                removed += 1
    return removed


def strip_javascript(doc: fitz.Document):
    """Remove document-level JavaScript that could reference PII."""
    try:
        # PyMuPDF exposes JS via the PDF catalog; scrub the /Names /JavaScript tree
        doc.scrub(javascript=True)
    except (AttributeError, Exception):
        pass


def strip_bookmarks(doc: fitz.Document) -> int:
    """Remove all bookmarks/outlines (table of contents) that could contain names."""
    removed = 0
    try:
        toc = doc.get_toc()
        if toc:
            removed = len(toc)
            doc.set_toc([])
    except Exception:
        pass
    return removed


def strip_link_uris(doc: fitz.Document) -> int:
    """Remove hyperlink annotations that could contain PII in URIs."""
    removed = 0
    for page in doc:
        for link in list(page.get_links()):
            if link.get("uri"):
                page.delete_link(link)
                removed += 1
    return removed


def redact_pdf(input_path: str, output_path: str,
               addresses: list[str] | None = None,
               names: list[str] | None = None,
               dry_run: bool = False):
    """
    Open input_path, apply redaction boxes over all PII matches,
    scrub form fields, strip metadata/signatures/JS/bookmarks/links.
    If dry_run is True, only report what would be redacted.
    """
    all_patterns: list[re.Pattern] = (
        list(SSN_PATTERNS) + list(ITIN_PATTERNS) + list(EIN_PATTERNS)
        + list(BANK_PATTERNS) + list(PHONE_PATTERNS) + list(EMAIL_PATTERNS)
        + list(W2_PATTERNS) + list(DOB_PATTERNS) + list(PTIN_PATTERNS)
        + list(IP_PIN_PATTERNS)
    )
    if addresses:
        for addr in addresses:
            all_patterns.extend(build_address_patterns(addr))
    if names:
        for name in names:
            all_patterns.extend(build_name_patterns(name))

    # Patterns for checking individual form field values (short strings).
    # These are used by scrub_page_form_fields to decide which fields to destroy.
    field_pii_patterns: list[re.Pattern] = list(all_patterns) + [
        # Catch bare 9-digit values in form fields (SSN without formatting)
        re.compile(r'^\d{9}$'),
        # Catch bare SSN with dashes in a field
        re.compile(r'^\d{3}-\d{2}-\d{4}$'),
        # Catch EIN in a field
        re.compile(r'^\d{2}-\d{7}$'),
    ]

    total_redactions = 0
    total_fields_scrubbed = 0

    with fitz.open(input_path) as doc:
        for page_num, page in enumerate(doc):
            page_text = page.get_text("text")

            # Collect widget info (used by both pattern matching and field scrubbing)
            page_widgets = []
            widget = page.first_widget
            while widget:
                page_widgets.append((
                    fitz.Rect(widget.rect) if widget.rect else None,
                    widget,
                    widget.field_value or "",
                ))
                widget = widget.next

            matched_texts: set[str] = set()
            for pattern in all_patterns:
                for match in pattern.finditer(page_text):
                    matched_texts.add(match.group())
                # Check individual field values (not joined — joining creates
                # phantom cross-boundary matches between unrelated fields)
                for _, _, val in page_widgets:
                    if val.strip():
                        for match in pattern.finditer(val):
                            matched_texts.add(match.group())

            # Single call to get_text("words") — shared by digit-box
            # detection and bare-digit redaction below
            page_words = page.get_text("words")

            digit_box_hits = find_digit_box_sequences(page_words)

            if dry_run:
                for text in sorted(matched_texts):
                    print(f"  Page {page_num + 1}: would redact {text!r}")
                for rect, digits in digit_box_hits:
                    print(f"  Page {page_num + 1}: would redact digit-box sequence {digits!r}")
                total_redactions += len(matched_texts) + len(digit_box_hits)
                continue

            # For bare digit strings, use page_words to find exact word
            # locations — search_for() matches digits scattered across
            # unrelated numbers on the page, producing huge bogus rects.
            page_redactions = 0
            for text in matched_texts:
                is_bare_digits = text.strip().isdigit()

                if is_bare_digits:
                    rects = [
                        fitz.Rect(w[0], w[1], w[2], w[3])
                        for w in page_words
                        if w[4].strip() == text  # exact match only
                    ]
                else:
                    rects = page.search_for(text)

                for rect in rects:
                    # Skip bogus rects from search_for matching scattered
                    # characters — real single-line text is never >30pt tall
                    if rect.height > 30:
                        continue
                    page.add_redact_annot(
                        rect,
                        text=REDACT_LABEL,
                        fontsize=8,
                        fill=(0, 0, 0),
                        text_color=(1, 1, 1),
                    )
                    page_redactions += 1

            # Add redactions for digit-per-box sequences (spanning rect)
            for rect, digits in digit_box_hits:
                page.add_redact_annot(
                    rect,
                    text=REDACT_LABEL,
                    fontsize=6,
                    fill=(0, 0, 0),
                    text_color=(1, 1, 1),
                )
                page_redactions += 1

            fields_scrubbed = scrub_page_form_fields(page, page_widgets, field_pii_patterns)

            # Single apply_redactions() destroys both text and field appearances
            if page_redactions > 0 or fields_scrubbed > 0:
                page.apply_redactions()
            if page_redactions > 0:
                total_redactions += page_redactions
                print(f"  Page {page_num + 1}: {page_redactions} redaction(s)")
            if fields_scrubbed > 0:
                total_fields_scrubbed += fields_scrubbed

        if dry_run:
            print(f"\nDry run complete. {total_redactions} match(es) found.")
            print("No file was modified.")
            return total_redactions

        if total_fields_scrubbed:
            print(f"  Form fields destroyed: {total_fields_scrubbed}")

        annots_removed = strip_annotations(doc)
        if annots_removed:
            print(f"  Annotations removed: {annots_removed}")

        embeds_removed = strip_embedded_files(doc)
        if embeds_removed:
            print(f"  Embedded files removed: {embeds_removed}")

        bookmarks_removed = strip_bookmarks(doc)
        if bookmarks_removed:
            print(f"  Bookmarks removed: {bookmarks_removed}")

        links_removed = strip_link_uris(doc)
        if links_removed:
            print(f"  Link URIs removed: {links_removed}")

        strip_javascript(doc)
        strip_metadata(doc)
        print(f"  Metadata/JS stripped")

        # garbage=4 purges unreferenced objects (old appearance streams,
        # deleted annotations, etc.) from the file
        doc.save(output_path, deflate=True, garbage=4)

    print(f"\nDone. {total_redactions} text redaction(s) applied.")
    print(f"Output: {output_path}")
    return total_redactions


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Redact PII (SSNs, ITINs, EINs, bank info, phone, email, W-2 fields, addresses, names) from a PDF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Redact only SSNs/EINs/bank info
  python redact_pdf.py document.pdf

  # Redact SSNs + address + name
  python redact_pdf.py document.pdf -a "123 Main St, Springfield, IL 62701" -n "John Public"

  # Multiple addresses and names
  python redact_pdf.py document.pdf -o clean.pdf \\
      -a "123 Main St, Springfield, IL 62701" \\
      -a "456 Oak Avenue, Apt 2B, Chicago, IL 60601" \\
      -n "John Q. Public" -n "Jane Doe"

  # Dry run — see what would be redacted without modifying
  python redact_pdf.py document.pdf --dry-run
        """,
    )
    parser.add_argument("input", help="Input PDF file path")
    parser.add_argument("-o", "--output", default=None, help="Output PDF path (default: input_redacted.pdf)")
    parser.add_argument(
        "--address", "-a",
        action="append",
        default=[],
        help="Address to redact (repeatable). Variations are auto-expanded.",
    )
    parser.add_argument(
        "--name", "-n",
        action="append",
        default=[],
        help="Person name to redact (repeatable). Matches first/last, last/first, initials, etc.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show what would be redacted without modifying the file.",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = args.output
    else:
        output_path = str(input_path.parent / f"{input_path.stem}_redacted.pdf")

    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    if args.dry_run:
        print(f"** DRY RUN — no files will be modified **")
    print(f"Redacting: SSNs + ITINs + EINs + bank info + phone + email + DOB + PTIN + IP PIN + W-2 fields")
    print(f"Also: form fields, signatures, annotations, embeds, bookmarks, links, JS, metadata")
    if args.address:
        for i, addr in enumerate(args.address, 1):
            print(f"  Address {i}: {addr}")
    if args.name:
        for i, name in enumerate(args.name, 1):
            print(f"  Name {i}: {name}")
    print()

    redact_pdf(
        str(input_path), output_path,
        args.address if args.address else None,
        args.name if args.name else None,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
