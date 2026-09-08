# PDF Unicode support

## Current guarantee

The canonical JSON report is UTF-8 and retains Unicode endpoint names, usernames,
software names, findings, and tenant branding exactly.

The dependency-free PDF renderer currently uses PDF's built-in Helvetica fonts with
Windows-1252 encoding. It renders ASCII and supported Western European characters
without replacing them. If any displayed value needs a character outside Windows-1252,
PDF generation fails with `PdfRenderError`. This fail-closed behavior is deliberate: an
enterprise report must not silently change a device, user, organization, or finding name
to `?`.

This means the current PDF renderer does **not** yet provide arbitrary Unicode body-text
support. The JSON report remains complete and is the authoritative evidence artifact.

## Why a code-only fallback is unsafe

PDF's standard Type 1 fonts do not contain Cyrillic, Greek, CJK, Indic, Arabic, or most
other Unicode glyphs. UTF-8 or UTF-16 bytes alone do not make those glyphs available.
Viewer-side font substitution is inconsistent and does not provide reliable text
extraction. Complex scripts also require shaping; mapping code points directly to glyphs
can display incorrect text even when a font contains the characters.

No redistributable Unicode font or shaping engine is currently present in this repository
or its pinned runtime. Microsoft fonts installed on a developer workstation must not be
copied into the product without redistribution rights.

## Smallest production-safe implementation

1. Select a redistribution-approved font family and coverage policy. A practical policy
   is a reviewed Noto font set for the customer languages rather than an unbounded font
   search on the host.
2. Commit the exact font files and their license notices as immutable release assets.
   Record SHA-256 hashes in the release manifest and include them in SBOM and license
   review.
3. Add a pinned text-shaping/font-subsetting implementation. It must shape complex scripts,
   embed only required glyphs as PDF Type 0/CID fonts, and emit a `ToUnicode` map so search,
   copy, accessibility tools, and text extraction recover the original Unicode.
4. Load fonts only from the immutable application asset directory. Reject symlinks,
   unexpected hashes, oversized files, unsupported formats, and missing glyphs. Never
   accept a font path or font upload from report data or an API caller.
5. Keep the existing page, row, cell, and output-size limits. Apply separate limits to
   glyph count, font bytes, shaping work, and fallback-font count.
6. Add tests for Latin, Cyrillic, Arabic, Devanagari, CJK, combining marks, bidirectional
   text, emoji policy, malicious control characters, missing glyphs, text extraction, and
   deterministic output. Validate the generated files with a strict PDF parser and the
   accessibility profile selected by the product.

Until these assets and dependencies pass legal, security, and release review, the current
explicit error is safer than a report that looks valid but changes evidence.
