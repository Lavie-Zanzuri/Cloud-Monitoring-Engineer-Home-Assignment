"""Attachment analysis.

We only look at the file NAME (and declared type). We never open or run the
file - the detector must be safe to run on malicious input.
"""
from __future__ import annotations

from ..models import Attachment, Finding, ParsedEmail

# Files that run code when the user double-clicks them.
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "hta", "jar", "msi", "lnk", "iso", "img", "reg", "cpl",
}
# Office documents that can contain macros (code that runs inside Word/Excel).
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppsm"}
# Archives can hide a dangerous file inside and slip past filters.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}
# Harmless-looking types an attacker pretends the file is ("invoice.pdf.exe").
DECOY_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
    "jpg", "jpeg", "png", "gif", "csv", "html", "htm",
}

POINTS_DANGEROUS = 30
POINTS_DOUBLE_EXTENSION = 20
POINTS_MACRO = 20
POINTS_ARCHIVE = 10


def _extensions(filename: str) -> list[str]:
    """'Invoice.PDF.exe ' -> ['pdf', 'exe']  (everything after the first dot, lowercased)."""
    parts = filename.strip().strip(".").lower().split(".")
    return [p.strip() for p in parts[1:] if p.strip()]


def _check_one(att: Attachment) -> list[Finding]:
    exts = _extensions(att.filename)
    if not exts:
        return []
    last = exts[-1]
    findings: list[Finding] = []

    if last in DANGEROUS_EXTENSIONS:
        findings.append(Finding(
            category="attachments",
            title="Dangerous attachment type",
            detail=f"'{att.filename}' is an executable/script file (.{last})",
            points=POINTS_DANGEROUS,
        ))
    elif last in MACRO_EXTENSIONS:
        findings.append(Finding(
            category="attachments",
            title="Macro-enabled Office document",
            detail=f"'{att.filename}' can contain macros (.{last})",
            points=POINTS_MACRO,
        ))
    elif last in ARCHIVE_EXTENSIONS:
        findings.append(Finding(
            category="attachments",
            title="Archive attachment",
            detail=f"'{att.filename}' is an archive (.{last}) that may hide other files",
            points=POINTS_ARCHIVE,
        ))

    # Double extension: a harmless-looking type right before a dangerous one.
    # "invoice.pdf.exe" -> suspicious;  "my.vacation.photos.zip" -> not
    # (because "photos" is not a document/image type).
    if (len(exts) >= 2 and exts[-2] in DECOY_EXTENSIONS
            and last in DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS):
        findings.append(Finding(
            category="attachments",
            title="Double file extension",
            detail=f"'{att.filename}' pretends to be .{exts[-2]} but is really .{last}",
            points=POINTS_DOUBLE_EXTENSION,
        ))
    return findings


def check_attachments(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for att in email.attachments:
        findings.extend(_check_one(att))
    return findings
