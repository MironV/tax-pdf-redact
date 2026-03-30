# Tax PDF Redacter

Redact sensitive PII from tax return PDFs so you can safely pass them to AI tools for analysis.

**No guarantees.** Always review the output before sharing. This tool makes a best effort to find and redact common PII patterns, but it may miss some or over-redact others depending on your PDF's structure.

## What it redacts

**Automatically (no flags needed):**
- SSNs, ITINs, EINs / Tax IDs
- Bank account and routing numbers
- Phone numbers and email addresses
- Dates of birth (label-required only -- won't touch tax year dates)
- Preparer PTIN and IRS Identity Protection PINs
- W-2 specific fields (control number, state employer ID, name blocks)
- Digit-per-box SSN sequences (common on IRS/state forms)

**With flags:**
- `-n` / `--name` -- Person names (generates first/last, last/first, initials, standalone variants)
- `-a` / `--address` -- Addresses (auto-expands abbreviations: St/Street, Ave/Avenue, etc.)

**PDF-level cleanup:**
- Strips metadata (author, creator, title, etc.)
- Scrubs interactive form fields containing PII
- Removes embedded file attachments (TurboTax XML data files)
- Removes annotations, digital signatures, JavaScript, bookmarks, and link URIs

## Install

```bash
pip install pymupdf
```

## Usage

```bash
# Redact just SSNs/EINs/bank info/phone/email (auto-detected)
python redact_pdf.py tax_return.pdf

# Add names and addresses
python redact_pdf.py tax_return.pdf \
  -n "John Q. Public" \
  -n "Jane Doe" \
  -a "123 Main St, Springfield, IL 62701"

# Custom output path
python redact_pdf.py tax_return.pdf -o redacted.pdf

# Dry run -- see what would be redacted without modifying
python redact_pdf.py tax_return.pdf --dry-run -n "John Public"
```

Multiple `-n` and `-a` flags can be repeated for additional names/addresses.

## Tested on

- IRS Form 1040, 1040-NR
- California 540, 540NR, Schedule CA, Form 3801
- W-2s (both interactive and flattened)
- TurboTax-generated PDFs

## Limitations

- **Scanned/image-only PDFs** -- Text redaction only works on PDFs with selectable text. Scanned documents need OCR first.
- **Dollar amounts** -- The tool avoids redacting dollar amounts, but unusual formatting could cause edge cases.
- **Name false positives** -- Short standalone names (4+ chars) are matched anywhere on the page. Common names that appear in form instructions could be over-redacted.
- **No guarantees** -- Always open the redacted PDF and verify sensitive information was properly removed before sharing.
