"""Data structures shared by the parser, the checks and the scorer.

Keeping these in one place means every check receives the same, already-parsed
view of the email and returns findings in the same shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Link:
    url: str            # where the link really goes (href)
    display_text: str   # what the user sees ("" for plain-text links)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    from_name: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    body_text: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    # e.g. {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    auth_results: dict[str, str] = field(default_factory=dict)
    has_headers: bool = False   # False when the input was just pasted body text


@dataclass
class Finding:
    """One suspicious thing a check found. The scorer adds up `points`."""
    category: str   # "sender" | "links" | "wording" | "attachments" | "authentication"
    title: str      # short label, e.g. "Dangerous attachment type"
    detail: str     # the evidence, e.g. "invoice.pdf.exe is an executable (.exe)"
    points: int     # how much this finding adds to the risk score
