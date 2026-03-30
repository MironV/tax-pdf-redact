# Redact Tax PDF

Redact sensitive PII from tax return PDFs so they can be safely shared with AI tools.

## When to use

Use this skill when you need to redact personally identifiable information from tax documents (1040, W-2, state returns, etc.) before passing them to AI for analysis.

## How to use

The tool is a Python script at `redact_pdf.py`. It requires `pymupdf` (`pip install pymupdf`).

### Basic usage

```bash
python redact_pdf.py <input.pdf> [-o output.pdf] [-n "Name"] [-a "Address"] [--dry-run]
```

### Auto-detected PII (no flags needed)

SSNs, ITINs, EINs, bank routing/account numbers, phone numbers, email addresses, dates of birth, preparer PTINs, IP PINs, and W-2 specific fields.

### Flags

| Flag | Description |
|------|-------------|
| `-n "Name"` | Person name to redact. Repeatable. Matches many variants (First Last, Last First, initials, standalone first/last). |
| `-a "Address"` | Address to redact. Repeatable. Auto-expands abbreviations (St/Street, Ave/Avenue, N/North, etc.) and handles unit-appended formats (1936A). |
| `-o path` | Output PDF path. Default: `<input>_redacted.pdf` |
| `--dry-run` | Show what would be redacted without modifying the file. |

### PDF-level cleanup (always applied)

Strips metadata, embedded file attachments (TurboTax XML), annotations, JavaScript, bookmarks, and link URIs.

### Example

```bash
python redact_pdf.py 2024_tax_return.pdf \
  -n "John Q. Public" \
  -n "Jane Doe" \
  -a "123 Main St, Apt 4B, Springfield, IL 62701" \
  -o 2024_tax_return_redacted.pdf
```

### Important

**No guarantees.** Always review the redacted PDF before sharing. The tool makes a best effort but may miss PII or over-redact depending on PDF structure.
